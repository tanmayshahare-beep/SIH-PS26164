"""Source code detector for Python using tree-sitter."""

import contextlib

import tree_sitter
import tree_sitter_python as tspython

from cbomscan.models import Occurrence

# Language setup
PY_LANGUAGE = tree_sitter.Language(tspython.language())
PY_PARSER = tree_sitter.Parser(PY_LANGUAGE)

# Map of crypto API calls to algorithm info
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
    "cryptography.hazmat.primitives.hashes.SHA3_256": {"name": "SHA3-256", "primitive": "hash"},
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
                                    module_name = source[n.start_byte:n.end_byte].decode()
                                elif n.type == "identifier":
                                    alias = source[n.start_byte:n.end_byte].decode()
                            if alias:
                                imports[alias] = module_name
                elif child.type == "dotted_name":
                    module_name = source[child.start_byte:child.end_byte].decode()
                    parts = module_name.split(".")
                    if parts:
                        imports[parts[-1]] = module_name
        elif node.type == "import_from_statement":
            module_name = ""
            for child in node.children:
                if child.type == "dotted_name":
                    # First dotted_name is the module, subsequent ones could be imports
                    if not module_name:
                        module_name = source[child.start_byte:child.end_byte].decode()
                    else:
                        # This is an imported name - it's a submodule or object
                        # from the module
                        name = source[child.start_byte:child.end_byte].decode()
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
                                    name = source[n.start_byte:n.end_byte].decode()
                                    imports[name] = f"{module_name}.{name}"
                                elif n.type == "aliased_import":
                                    orig = ""
                                    alias = ""
                                    for nn in n.children:
                                        if nn.type == "identifier" and not orig:
                                            orig = source[nn.start_byte:nn.end_byte].decode()
                                        elif nn.type == "identifier":
                                            alias = source[nn.start_byte:nn.end_byte].decode()
                                    if alias:
                                        imports[alias] = f"{module_name}.{orig}"
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
                parts.append(source[attr.start_byte:attr.end_byte].decode())
            current = current.child_by_field_name("object")
        if current.type == "identifier":
            base = source[current.start_byte:current.end_byte].decode()
            parts.append(base)
            parts.reverse()
            full_name = ".".join(parts)

            # Try to resolve base via imports
            if parts[0] in imports:
                return f"{imports[parts[0]]}.{'.'.join(parts[1:])}"
            return full_name
    elif node.type == "identifier":
        name = source[node.start_byte:node.end_byte].decode()
        if name in imports:
            return imports[name]
        return name
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
                        key = source[key_node.start_byte:key_node.end_byte].decode()
                        val = source[val_node.start_byte:val_node.end_byte].decode()
                        args[key] = val
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
    supported_extensions = [".py"]

    def __init__(self):
        self.parser = PY_PARSER

    def detect(self, file_path: str, content: str) -> list:
        """Detect cryptographic artifacts in a Python file."""
        from cbomscan.detectors import RawFinding

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
                        if (line, symbol) in seen:
                            pass
                        else:
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
                                            algo_info["curve"] = (
                                                curve_name.lower().replace("secp", "secp")
                                            )
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
