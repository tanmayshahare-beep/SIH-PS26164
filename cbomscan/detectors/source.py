"""Source code detector for Python and JavaScript/TypeScript using tree-sitter."""

import contextlib
import re

import tree_sitter
import tree_sitter_javascript as tsjavascript
import tree_sitter_python as tspython

from cbomscan.models import Occurrence, RawFinding

# Language setup
PY_LANGUAGE = tree_sitter.Language(tspython.language())
PY_PARSER = tree_sitter.Parser(PY_LANGUAGE)

JS_LANGUAGE = tree_sitter.Language(tsjavascript.language())
JS_PARSER = tree_sitter.Parser(JS_LANGUAGE)

# Map of crypto API calls to algorithm info for Python
# Format: "module_path.function_name" -> {name, primitive, key_size, curve}
CRYPTO_API_MAP = {
    # cryptography.hazmat.primitives.asymmetric.rsa
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": {
        "name": "RSA",
        "primitive": "pke",
        "key_size": 2048,
    },
    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey": {
        "name": "RSA",
        "primitive": "pke",
        "key_size": 2048,
    },
    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey": {
        "name": "RSA",
        "primitive": "pke",
        "key_size": 2048,
    },
    # cryptography.hazmat.primitives.asymmetric.ec
    "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": {
        "name": "ECDSA",
        "primitive": "signature",
    },
    "cryptography.hazmat.primitives.asymmetric.ec.ECDSA": {
        "name": "ECDSA",
        "primitive": "signature",
    },
    "cryptography.hazmat.primitives.asymmetric.ec.ECDH": {
        "name": "ECDH",
        "primitive": "key-agree",
    },
    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey": {
        "name": "ECDSA",
        "primitive": "signature",
    },
    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey": {
        "name": "ECDSA",
        "primitive": "signature",
    },
    "cryptography.hazmat.primitives.asymmetric.ec.SECP256R1": {"curve": "secp256r1"},
    "cryptography.hazmat.primitives.asymmetric.ec.SECP384R1": {"curve": "secp384r1"},
    "cryptography.hazmat.primitives.asymmetric.ec.SECP521R1": {"curve": "secp521r1"},
    "cryptography.hazmat.primitives.asymmetric.ec.SECP256K1": {"curve": "secp256k1"},
    # cryptography.hazmat.primitives.asymmetric.dh
    "cryptography.hazmat.primitives.asymmetric.dh.generate_private_key": {
        "name": "DH",
        "primitive": "key-agree",
    },
    "cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey": {
        "name": "DH",
        "primitive": "key-agree",
    },
    "cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey": {
        "name": "DH",
        "primitive": "key-agree",
    },
    # cryptography.hazmat.primitives.asymmetric.ed25519
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey": {
        "name": "Ed25519",
        "primitive": "signature",
    },
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey": {
        "name": "Ed25519",
        "primitive": "signature",
    },
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate": {
        "name": "Ed25519",
        "primitive": "signature",
    },
    "cryptography.hazmat.primitives.asymmetric.ed25519.generate_private_key": {
        "name": "Ed25519",
        "primitive": "signature",
    },
    # cryptography.hazmat.primitives.asymmetric.x25519
    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey": {
        "name": "X25519",
        "primitive": "key-agree",
    },
    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey": {
        "name": "X25519",
        "primitive": "key-agree",
    },
    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate": {
        "name": "X25519",
        "primitive": "key-agree",
    },
    "cryptography.hazmat.primitives.asymmetric.x25519.generate_private_key": {
        "name": "X25519",
        "primitive": "key-agree",
    },
    # cryptography.hazmat.primitives.hashes
    "cryptography.hazmat.primitives.hashes.MD5": {"name": "MD5", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA1": {"name": "SHA-1", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA224": {"name": "SHA-224", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA256": {"name": "SHA-256", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA384": {"name": "SHA-384", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA512": {"name": "SHA-512", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA3_224": {"name": "SHA3-224", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA3_254": {"name": "SHA3-256", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA3_384": {"name": "SHA3-384", "primitive": "hash"},
    "cryptography.hazmat.primitives.hashes.SHA3_512": {"name": "SHA3-512", "primitive": "hash"},
    # hashlib
    "hashlib.md5": {"name": "MD5", "primitive": "hash"},
    "hashlib.sha1": {"name": "SHA-1", "primitive": "hash"},
    "hashlib.sha224": {"name": "SHA-224", "primitive": "hash"},
    "hashlib.sha256": {"name": "SHA-256", "primitive": "hash"},
    "hashlib.sha384": {"name": "SHA-384", "primitive": "hash"},
    "hashlib.sha512": {"name": "SHA-512", "primitive": "hash"},
    "hashlib.sha3_224": {"name": "SHA3-224", "primitive": "hash"},
    "hashlib.sha3_256": {"name": "SHA3-256", "primitive": "hash"},
    "hashlib.sha3_384": {"name": "SHA3-384", "primitive": "hash"},
    "hashlib.sha3_512": {"name": "SHA3-512", "primitive": "hash"},
    "hashlib.blake2b": {"name": "BLAKE2b", "primitive": "hash"},
    "hashlib.blake2s": {"name": "BLAKE2s", "primitive": "hash"},
    # ssl
    "ssl.create_default_context": {"name": "TLS", "primitive": "protocol"},
    "ssl.SSLContext": {"name": "TLS", "primitive": "protocol"},
    "ssl.PROTOCOL_TLS": {"name": "TLS", "primitive": "protocol"},
    "ssl.PROTOCOL_TLS_CLIENT": {"name": "TLS", "primitive": "protocol"},
    "ssl.PROTOCOL_TLS_SERVER": {"name": "TLS", "primitive": "protocol"},
    # cryptography.hazmat.primitives.ciphers
    "cryptography.hazmat.primitives.ciphers.Cipher": {"primitive": "block-cipher"},
    "cryptography.hazmat.primitives.ciphers.algorithms.AES": {
        "name": "AES-256",
        "primitive": "block-cipher",
        "key_size": 256,
    },
    "cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20": {
        "name": "ChaCha20",
        "primitive": "stream-cipher",
        "key_size": 256,
    },
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES": {
        "name": "3DES",
        "primitive": "block-cipher",
        "key_size": 168,
    },
    # cryptography.hazmat.primitives.kdf
    "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2": {
        "name": "PBKDF2",
        "primitive": "kdf",
    },
    "cryptography.hazmat.primitives.kdf.hkdf.HKDF": {"name": "HKDF", "primitive": "kdf"},
    "cryptography.hazmat.primitives.kdf.scrypt.Scrypt": {"name": "Scrypt", "primitive": "kdf"},
    # cryptography.hazmat.primitives.hmac
    "cryptography.hazmat.primitives.hmac.HMAC": {"name": "HMAC", "primitive": "mac"},
}

# JavaScript/TypeScript crypto API patterns
# These are patterns to match in the AST for JS/TS
JS_CRYPTO_PATTERNS = {
    # Node.js crypto module patterns
    "node_crypto": {
        "generateKeyPair": {
            "rsa": {"name": "RSA", "primitive": "pke"},
            "ec": {"name": "ECDSA", "primitive": "signature"},
            "ed25519": {"name": "Ed25519", "primitive": "signature"},
            "ed448": {"name": "Ed448", "primitive": "signature"},
            "dh": {"name": "DH", "primitive": "key-agree"},
            "x25519": {"name": "X25519", "primitive": "key-agree"},
            "x448": {"name": "X448", "primitive": "key-agree"},
        },
        "generateKeyPairSync": {
            "rsa": {"name": "RSA", "primitive": "pke"},
            "ec": {"name": "ECDSA", "primitive": "signature"},
            "ed25519": {"name": "Ed25519", "primitive": "signature"},
            "ed448": {"name": "Ed448", "primitive": "signature"},
            "dh": {"name": "DH", "primitive": "key-agree"},
            "x25519": {"name": "X25519", "primitive": "key-agree"},
            "x448": {"name": "X448", "primitive": "key-agree"},
        },
        "createSign": {"name": "RSA", "primitive": "signature"},
        "createVerify": {"name": "RSA", "primitive": "signature"},
        "createECDH": {"name": "ECDH", "primitive": "key-agree"},
        "createDiffieHellman": {"name": "DH", "primitive": "key-agree"},
        "createDiffieHellmanGroup": {"name": "DH", "primitive": "key-agree"},
        "createCipher": {"primitive": "block-cipher"},
        "createDecipher": {"primitive": "block-cipher"},
        "createCipheriv": {"primitive": "block-cipher"},
        "createDecipheriv": {"primitive": "block-cipher"},
        "createHash": {"primitive": "hash"},
        "createHmac": {"name": "HMAC", "primitive": "mac"},
        "pbkdf2": {"name": "PBKDF2", "primitive": "kdf"},
        "pbkdf2Sync": {"name": "PBKDF2", "primitive": "kdf"},
        "scrypt": {"name": "Scrypt", "primitive": "kdf"},
        "scryptSync": {"name": "Scrypt", "primitive": "kdf"},
        "hkdf": {"name": "HKDF", "primitive": "kdf"},
        "hkdfSync": {"name": "HKDF", "primitive": "kdf"},
    },
    # Web Crypto API patterns
    "web_crypto": {
        "generateKey": {
            "RSA-OAEP": {"name": "RSA", "primitive": "pke"},
            "RSASSA-PKCS1-v1_5": {"name": "RSA", "primitive": "signature"},
            "RSA-PSS": {"name": "RSA", "primitive": "signature"},
            "ECDSA": {"name": "ECDSA", "primitive": "signature"},
            "ECDH": {"name": "ECDH", "primitive": "key-agree"},
            "AES-CTR": {"name": "AES", "primitive": "block-cipher"},
            "AES-CBC": {"name": "AES", "primitive": "block-cipher"},
            "AES-GCM": {"name": "AES", "primitive": "block-cipher"},
            "AES-KW": {"name": "AES", "primitive": "block-cipher"},
            "HMAC": {"name": "HMAC", "primitive": "mac"},
            "HKDF": {"name": "HKDF", "primitive": "kdf"},
            "PBKDF2": {"name": "PBKDF2", "primitive": "kdf"},
        },
        "sign": {"primitive": "signature"},
        "verify": {"primitive": "signature"},
        "deriveKey": {"primitive": "key-agree"},
        "deriveBits": {"primitive": "key-agree"},
        "encrypt": {"primitive": "pke"},
        "decrypt": {"primitive": "pke"},
        "wrapKey": {"primitive": "pke"},
        "unwrapKey": {"primitive": "pke"},
        "digest": {"primitive": "hash"},
    },
    # JWT algorithm strings
    "jwt_algorithms": {
        "RS256": {"name": "RSA", "primitive": "signature"},
        "RS384": {"name": "RSA", "primitive": "signature"},
        "RS512": {"name": "RSA", "primitive": "signature"},
        "ES256": {"name": "ECDSA", "primitive": "signature"},
        "ES384": {"name": "ECDSA", "primitive": "signature"},
        "ES512": {"name": "ECDSA", "primitive": "signature"},
        "PS256": {"name": "RSA", "primitive": "signature"},
        "PS384": {"name": "RSA", "primitive": "signature"},
        "PS512": {"name": "RSA", "primitive": "signature"},
        "HS256": {"name": "HMAC", "primitive": "mac"},
        "HS384": {"name": "HMAC", "primitive": "mac"},
        "HS512": {"name": "HMAC", "primitive": "mac"},
        "EdDSA": {"name": "Ed25519", "primitive": "signature"},
    },
}


def _extract_imports(root_node: tree_sitter.Node, source: bytes) -> dict[str, str]:
    """Extract import aliases from the AST. Returns {alias: full_module_path}."""
    imports = {}

    def visit(node: tree_sitter.Node):
        if node.type == "import_statement":
            for child in node.children:
                if child.type in ("dotted_as_names", "aliased_import"):
                    name_nodes = child.children if child.type == "dotted_as_names" else [child]
                    for name_node in name_nodes:
                        if name_node.type in ("dotted_as_name", "aliased_import"):
                            module_name = ""
                            alias = None
                            for n in name_node.children:
                                if n.type == "dotted_name":
                                    module_name = source[n.start_byte : n.end_byte].decode()
                                elif n.type == "identifier":
                                    alias = source[n.start_byte : n.end_byte].decode()
                            if alias:
                                imports[alias] = module_name
                elif child.type == "dotted_name":
                    module_name = source[child.start_byte : child.end_byte].decode()
                    parts = module_name.split(".")
                    if parts:
                        imports[parts[-1]] = module_name
        elif node.type == "import_from_statement":
            module_name = ""
            for child in node.children:
                if child.type == "dotted_name":
                    # First dotted_name is the module, subsequent ones could be imports
                    if not module_name:
                        module_name = source[child.start_byte : child.end_byte].decode()
                    else:
                        # This is an imported name - it's a submodule or object
                        # from the module
                        name = source[child.start_byte : child.end_byte].decode()
                        # The full path is module_name + "." + name
                        # (since it's from module import name)
                        imports[name] = f"{module_name}.{name}"
                elif child.type == "wildcard_import":
                    pass
                elif child.type == "import_list":
                    for import_item in child.children:
                        if import_item.type == "import":
                            for n in import_item.children:
                                if n.type == "identifier":
                                    name = source[n.start_byte : n.end_byte].decode()
                                    imports[name] = f"{module_name}.{name}"
                                elif n.type == "aliased_import":
                                    orig = ""
                                    alias = ""
                                    for nn in n.children:
                                        if nn.type == "identifier" and not orig:
                                            orig = source[nn.start_byte : nn.end_byte].decode()
                                        elif nn.type == "identifier":
                                            alias = source[nn.start_byte : nn.end_byte].decode()
                                    if alias:
                                        imports[alias] = f"{module_name}.{orig}"
        for child in node.children:
            visit(child)

    visit(root_node)
    return imports


def _extract_js_imports(root_node: tree_sitter.Node, source: bytes) -> dict[str, str]:
    """Extract import aliases from JavaScript/TypeScript AST. Returns {alias: full_module_path}."""
    imports = {}

    def visit(node: tree_sitter.Node):
        # Handle import statements: import x from 'y', import {x} from 'y', import * as x from 'y'
        if node.type in ("import_statement", "lexical_declaration"):
            for child in node.children:
                if child.type == "import_clause":
                    # import x from 'y' or import {x} from 'y'
                    for grandchild in child.children:
                        if grandchild.type == "identifier":
                            # default import
                            module_node = child.next_sibling
                            while module_node and module_node.type != "string":
                                module_node = module_node.next_sibling
                            if module_node and module_node.type == "string":
                                module_name = source[
                                    module_node.start_byte : module_node.end_byte
                                ].decode()
                                module_name = module_name.strip("\"'").replace("/", ".")
                                imports[
                                    source[grandchild.start_byte : grandchild.end_byte].decode()
                                ] = module_name
                        elif grandchild.type == "named_imports":
                            # import {x, y} from 'z'
                            module_node = child.next_sibling
                            while module_node and module_node.type != "string":
                                module_node = module_node.next_sibling
                            if module_node and module_node.type == "string":
                                module_name = source[
                                    module_node.start_byte : module_node.end_byte
                                ].decode()
                                module_name = module_name.strip("\"'").replace("/", ".")
                                for spec in grandchild.children:
                                    if spec.type == "import_specifier":
                                        for spec_child in spec.children:
                                            if spec_child.type == "identifier":
                                                imports[
                                                    source[
                                                        spec_child.start_byte : spec_child.end_byte
                                                    ].decode()
                                                ] = module_name
                elif child.type == "namespace_import":
                    # import * as x from 'y'
                    module_node = child.next_sibling
                    while module_node and module_node.type != "string":
                        module_node = module_node.next_sibling
                    if module_node and module_node.type == "string":
                        module_name = source[module_node.start_byte : module_node.end_byte].decode()
                        module_name = module_name.strip("\"'").replace("/", ".")
                        for grandchild in child.children:
                            if grandchild.type == "identifier":
                                imports[
                                    source[grandchild.start_byte : grandchild.end_byte].decode()
                                ] = module_name

        # Handle require() calls: const x = require('y')
        # Also handle destructuring: const { subtle } = require('crypto').webcrypto
        elif node.type == "variable_declarator":
            # Check for simple identifier (const x = require('y'))
            var_name = None
            for child in node.children:
                if child.type == "identifier":
                    var_name = source[child.start_byte : child.end_byte].decode()
                    break

            # Check for object pattern destructuring (const { subtle } = ...)
            if not var_name:
                for child in node.children:
                    if child.type == "object_pattern":
                        for pattern_child in child.children:
                            if pattern_child.type == "shorthand_property_identifier_pattern":
                                var_name = source[
                                    pattern_child.start_byte : pattern_child.end_byte
                                ].decode()
                                break

            if var_name:
                # Check for require() call on the right side
                for child in node.children:
                    if child.type == "call_expression":
                        for grandchild in child.children:
                            if (
                                grandchild.type == "identifier"
                                and source[grandchild.start_byte : grandchild.end_byte].decode()
                                == "require"
                            ):
                                # Find the argument
                                for arg in child.children:
                                    if arg.type == "arguments":
                                        for arg_child in arg.children:
                                            if arg_child.type == "string":
                                                module_name = source[
                                                    arg_child.start_byte : arg_child.end_byte
                                                ].decode()
                                                module_name = module_name.strip("\"'")
                                                imports[var_name] = module_name
                                                break
                    # Also handle member expressions like require('crypto').webcrypto
                    elif child.type == "member_expression":
                        obj = child.child_by_field_name("object")
                        prop = child.child_by_field_name("property")
                        if obj and obj.type == "call_expression":
                            # Check if it's require('something')
                            for gc in obj.children:
                                if (
                                    gc.type == "identifier"
                                    and source[gc.start_byte : gc.end_byte].decode() == "require"
                                ):
                                    for arg in obj.children:
                                        if arg.type == "arguments":
                                            for arg_child in arg.children:
                                                if arg_child.type == "string":
                                                    module_name = source[
                                                        arg_child.start_byte : arg_child.end_byte
                                                    ].decode()
                                                    module_name = module_name.strip("\"'")
                                                    if prop:
                                                        prop_name = source[
                                                            prop.start_byte : prop.end_byte
                                                        ].decode()
                                                        imports[var_name] = (
                                                            f"{module_name}.{prop_name}"
                                                        )
                                                    else:
                                                        imports[var_name] = module_name
        for child in node.children:
            visit(child)

    visit(root_node)
    return imports


def _resolve_name(node: tree_sitter.Node, source: bytes, imports: dict[str, str]) -> str | None:
    """Resolve a function/class name to its full module path using imports."""
    if node.type == "attribute":
        # Handle chained attributes like module.submodule.Class
        parts = []
        current = node
        while current.type == "attribute":
            attr = current.child_by_field_name("attribute")
            if attr:
                parts.append(source[attr.start_byte : attr.end_byte].decode())
            current = current.child_by_field_name("object")
        if current.type == "identifier":
            base = source[current.start_byte : current.end_byte].decode()
            parts.append(base)
            parts.reverse()
            full_name = ".".join(parts)

            # Try to resolve base via imports
            if parts[0] in imports:
                return f"{imports[parts[0]]}.{'.'.join(parts[1:])}"
            return full_name
    elif node.type == "identifier":
        name = source[node.start_byte : node.end_byte].decode()
        if name in imports:
            return imports[name]
        return name
    return None


def _resolve_js_name(node: tree_sitter.Node, source: bytes, imports: dict[str, str]) -> str | None:
    """Resolve a JavaScript/TypeScript function/class name."""
    if node.type == "member_expression":
        # Handle chained member expressions like crypto.generateKeyPair
        parts = []
        current = node
        while current.type == "member_expression":
            prop = current.child_by_field_name("property")
            if prop:
                parts.append(source[prop.start_byte : prop.end_byte].decode())
            current = current.child_by_field_name("object")
        if current.type == "identifier":
            base = source[current.start_byte : current.end_byte].decode()
            parts.append(base)
            parts.reverse()
            full_name = ".".join(parts)

            # Try to resolve base via imports
            if parts[0] in imports:
                return f"{imports[parts[0]]}.{'.'.join(parts[1:])}"
            return full_name
    elif node.type == "identifier":
        name = source[node.start_byte : node.end_byte].decode()
        if name in imports:
            return imports[name]
        return name
    elif node.type == "call_expression":
        # For direct calls like generateKeyPair()
        return _resolve_js_name(node.child_by_field_name("function"), source, imports)
    return None


def _find_call_args(node: tree_sitter.Node, source: bytes) -> dict:
    """Extract keyword arguments from a call node."""
    args = {}
    if node.type != "call":
        return args
    for child in node.children:
        if child.type == "argument_list":
            for arg in child.children:
                if arg.type == "keyword_argument":
                    key_node = child_by_field_name(arg, "name")
                    val_node = child_by_field_name(arg, "value")
                    if key_node and val_node:
                        key = source[key_node.start_byte : key_node.end_byte].decode()
                        val = source[val_node.start_byte : val_node.end_byte].decode()
                        args[key] = val
    return args


def _find_js_call_args(node: tree_sitter.Node, source: bytes) -> list:
    """Extract positional arguments from a JavaScript call node."""
    args = []
    if node.type != "call_expression":
        return args
    for child in node.children:
        if child.type == "arguments":
            for arg in child.children:
                if arg.type != "," and arg.type != "(" and arg.type != ")":
                    args.append(source[arg.start_byte : arg.end_byte].decode())
    return args


def child_by_field_name(node: tree_sitter.Node, field_name: str) -> tree_sitter.Node | None:
    """Get child by field name."""
    for i in range(node.child_count):
        if node.field_name_for_child(i) == field_name:
            return node.child(i)
    return None


class PythonSourceDetector:
    """Detector for Python source files using tree-sitter."""

    name = "python_source"
    title = "Python Source Detector"
    summary = "Finds cryptographic API calls in Python source via tree-sitter AST parsing."
    detail = (
        "Walks the tree-sitter AST, resolves imports to fully-qualified names, and "
        "matches call sites against a map of known crypto APIs. Key sizes and curves "
        "are read from the call's own arguments where present."
    )
    typical_confidence = "confirmed"
    inputs = [".py"]
    detects = [
        "cryptography.hazmat primitives (RSA, EC, Ed25519, X25519, DH, AES, ChaCha20, 3DES)",
        "hashlib digests (MD5, SHA-1, SHA-2, SHA-3, BLAKE2)",
        "KDFs and MACs (PBKDF2, HKDF, Scrypt, HMAC)",
        "ssl / TLS context construction",
    ]
    supported_extensions = [".py"]

    def __init__(self):
        self.parser = PY_PARSER

    def detect(self, file_path: str, content: str) -> list:
        """Detect cryptographic artifacts in a Python file."""

        findings = []
        source_bytes = content.encode("utf-8")

        try:
            tree = self.parser.parse(source_bytes)
            root = tree.root_node
        except Exception:
            return findings

        # Extract imports
        imports = _extract_imports(root, source_bytes)

        def _get_call_function(node: tree_sitter.Node) -> tree_sitter.Node | None:
            """Get the actual function being called, unwrapping chained calls like foo().bar()."""
            func_node = child_by_field_name(node, "function")
            while func_node and func_node.type == "attribute":
                obj_node = child_by_field_name(func_node, "object")
                if obj_node and obj_node.type == "call":
                    # This is a chained call like foo().bar(), get the inner call's function
                    func_node = child_by_field_name(obj_node, "function")
                else:
                    break
            return func_node

        # Visit all call expressions
        def visit(node: tree_sitter.Node):
            if node.type == "call":
                # Get the function being called, unwrapping chained calls
                func_node = _get_call_function(node)
                if func_node:
                    full_name = _resolve_name(func_node, source_bytes, imports)
                    if full_name and full_name in CRYPTO_API_MAP:
                        # Deduplicate by line and symbol
                        line = node.start_point[0] + 1
                        symbol = full_name
                        if (line, symbol) not in seen:
                            seen.add((line, symbol))
                            algo_info = CRYPTO_API_MAP[full_name].copy()

                            # Try to extract key_size from arguments for RSA
                            if algo_info.get("name") == "RSA" and "key_size" not in algo_info:
                                args = _find_call_args(node, source_bytes)
                                if "key_size" in args:
                                    with contextlib.suppress(ValueError):
                                        algo_info["key_size"] = int(args["key_size"])

                            # Try to extract curve for EC
                            if "curve" not in algo_info:
                                args = _find_call_args(node, source_bytes)
                                if "curve" in args:
                                    curve_val = args["curve"]
                                    # Handle ec.SECP256R1() etc.
                                    for curve_name in (
                                        "SECP256R1",
                                        "SECP384R1",
                                        "SECP521R1",
                                        "SECP256K1",
                                    ):
                                        if curve_name in curve_val:
                                            algo_info["curve"] = curve_name.lower()
                                            break

                            # Extract algorithm from hashlib calls like hashlib.md5()
                            if full_name.startswith("hashlib."):
                                algo_name = full_name.split(".")[-1].upper()
                                if algo_name in [
                                    "MD5",
                                    "SHA1",
                                    "SHA224",
                                    "SHA256",
                                    "SHA384",
                                    "SHA512",
                                ]:
                                    algo_info["name"] = algo_name.replace("SHA", "SHA-")

                            occurrence = Occurrence(
                                file=file_path,
                                line=line,
                                symbol=symbol,
                            )

                            findings.append(
                                RawFinding(
                                    asset_type=algo_info.get("asset_type", "algorithm"),
                                    name=algo_info.get("name", "Unknown"),
                                    occurrences=[occurrence],
                                    primitive=algo_info.get("primitive"),
                                    key_size=algo_info.get("key_size"),
                                    curve=algo_info.get("curve"),
                                    confidence="confirmed",
                                )
                            )

            for child in node.children:
                visit(child)

        # Track seen (line, symbol) pairs to avoid double-detection of chained calls
        seen: set[tuple[int, str]] = set()
        visit(root)
        return findings


class JavaScriptSourceDetector:
    """Detector for JavaScript/TypeScript source files using tree-sitter."""

    name = "javascript_source"
    title = "JavaScript / TypeScript Source Detector"
    summary = "Finds cryptographic API calls in JS and TS source via tree-sitter AST parsing."
    detail = (
        "Resolves ESM imports and require() calls, then matches Node crypto, Web Crypto "
        "and JWT library call sites. Algorithm names are lifted from adjacent string "
        "literals and object arguments such as { name: 'ECDSA' } or 'RS256'."
    )
    typical_confidence = "confirmed"
    inputs = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
    detects = [
        "Node crypto (generateKeyPair, createSign, createECDH, createHash, createCipheriv)",
        "Web Crypto subtle API (generateKey, sign, verify, deriveKey, digest)",
        "JWT algorithm strings (RS256, ES256, PS512, HS256, EdDSA)",
    ]
    supported_extensions = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

    def __init__(self):
        self.parser = JS_PARSER

    def detect(self, file_path: str, content: str) -> list:
        """Detect cryptographic artifacts in a JavaScript/TypeScript file."""

        findings = []
        source_bytes = content.encode("utf-8")

        try:
            tree = self.parser.parse(source_bytes)
            root = tree.root_node
        except Exception:
            return findings

        # Extract imports
        imports = _extract_js_imports(root, source_bytes)

        # Visit all call expressions
        def visit(node: tree_sitter.Node):
            if node.type == "call_expression":
                func_node = child_by_field_name(node, "function")
                if func_node:
                    full_name = _resolve_js_name(func_node, source_bytes, imports)
                    if full_name:
                        self._check_js_crypto_call(
                            full_name, node, file_path, source_bytes, imports, findings
                        )

            for child in node.children:
                visit(child)

        visit(root)
        return findings

    def _check_js_crypto_call(
        self,
        full_name: str,
        node: tree_sitter.Node,
        file_path: str,
        source: bytes,
        imports: dict[str, str],
        findings: list,
    ):
        """Check if a JS call matches known crypto patterns."""

        line = node.start_point[0] + 1
        args = _find_js_call_args(node, source)

        # Check Web Crypto API patterns (must be before general crypto. check)
        if full_name.startswith("crypto.subtle.") or full_name.startswith("crypto.webcrypto."):
            method = full_name.split(".")[-1]
            if method in JS_CRYPTO_PATTERNS["web_crypto"]:
                pattern_info = JS_CRYPTO_PATTERNS["web_crypto"][method]

                # For generateKey, sign, verify - check first argument for algorithm
                if method in ("generateKey", "sign", "verify") and args:
                    # Try to extract from string literal first
                    algo_arg = _get_js_string_value_from_arg(args[0], source)
                    if not algo_arg:
                        # Try to extract from object literal { name: 'ECDSA', ... }
                        algo_arg = _extract_algo_from_object_arg(args[0])

                    # Check if pattern_info has algorithm-specific entries (like generateKey)
                    if isinstance(pattern_info, dict) and algo_arg and algo_arg in pattern_info:
                        algo_info = pattern_info[algo_arg].copy()
                        confidence = "confirmed"
                    elif algo_arg:
                        # For sign/verify, pattern_info is a simple dict with primitive
                        # Use the algorithm name from the argument
                        algo_info = pattern_info.copy()
                        algo_info["name"] = algo_arg
                        confidence = "confirmed"
                    else:
                        algo_info = {"name": "Unknown", "primitive": "pke"}
                        confidence = "inferred"
                else:
                    algo_info = pattern_info.copy()
                    confidence = "confirmed" if "name" in pattern_info else "inferred"

                occurrence = Occurrence(file=file_path, line=line, symbol=full_name)
                findings.append(
                    RawFinding(
                        asset_type="algorithm",
                        name=algo_info.get("name", "Unknown"),
                        occurrences=[occurrence],
                        primitive=algo_info.get("primitive"),
                        confidence=confidence,
                    )
                )

        # Check Node.js crypto patterns
        elif full_name.startswith("crypto."):
            method = full_name.split(".")[-1]
            if method in JS_CRYPTO_PATTERNS["node_crypto"]:
                pattern_info = JS_CRYPTO_PATTERNS["node_crypto"][method]

                # For generateKeyPair/generateKeyPairSync, check first argument for algorithm
                if method in ("generateKeyPair", "generateKeyPairSync") and args:
                    algo_arg = _get_js_string_value_from_arg(args[0], source)
                    if algo_arg and algo_arg in pattern_info:
                        algo_info = pattern_info[algo_arg].copy()
                        confidence = "confirmed"
                    else:
                        algo_info = {"name": "Unknown", "primitive": "pke"}
                        confidence = "inferred"
                else:
                    algo_info = pattern_info.copy()
                    confidence = "confirmed" if "name" in pattern_info else "inferred"

                occurrence = Occurrence(file=file_path, line=line, symbol=full_name)
                findings.append(
                    RawFinding(
                        asset_type="algorithm",
                        name=algo_info.get("name", "Unknown"),
                        occurrences=[occurrence],
                        primitive=algo_info.get("primitive"),
                        confidence=confidence,
                    )
                )

        # Check for JWT algorithm strings in function calls
        # Look for jwt.sign(), jose.sign(), etc. with algorithm parameter
        elif any(pkg in full_name for pkg in ["jwt.", "jose.", "jsonwebtoken.", "jws."]):
            # Check if any argument contains a known JWT algorithm
            for arg in args:
                # Check for string literal like 'RS256'
                algo_match = re.search(r"'([A-Z]{2,}\d+)'", arg)
                if algo_match:
                    algo_str = algo_match.group(1)
                    if algo_str in JS_CRYPTO_PATTERNS["jwt_algorithms"]:
                        algo_info = JS_CRYPTO_PATTERNS["jwt_algorithms"][algo_str].copy()
                        occurrence = Occurrence(file=file_path, line=line, symbol=full_name)
                        findings.append(
                            RawFinding(
                                asset_type="algorithm",
                                name=algo_info["name"],
                                occurrences=[occurrence],
                                primitive=algo_info.get("primitive"),
                                confidence="confirmed",
                            )
                        )
                        break


def _get_js_string_value_from_arg(arg_text: str, source: bytes) -> str | None:
    """Extract string value from an argument text."""
    # Remove quotes
    arg_text = arg_text.strip()
    if arg_text.startswith("'") and arg_text.endswith("'"):
        return arg_text[1:-1]
    if arg_text.startswith('"') and arg_text.endswith('"'):
        return arg_text[1:-1]
    if arg_text.startswith("`") and arg_text.endswith("`"):
        return arg_text[1:-1]
    return None


def _extract_algo_from_object_arg(arg_text: str) -> str | None:
    """Extract algorithm name from an object literal like { name: 'ECDSA', ... }."""
    # Look for name: 'value' or name: "value" pattern
    match = re.search(r"name\s*:\s*['\"`]([^'\"`]+)['\"`]", arg_text)
    if match:
        return match.group(1)
    return None
