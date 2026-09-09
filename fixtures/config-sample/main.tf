# Terraform configuration with cloud KMS references for CBOMScan testing

provider "aws" {
  region = "us-east-1"
}

# AWS KMS Key for encryption
resource "aws_kms_key" "app_key" {
  description             = "Application encryption key"
  deletion_window_in_days = 10
  key_usage               = "ENCRYPT_DECRYPT"
}

resource "aws_kms_alias" "app_key_alias" {
  name          = "alias/app-key"
  target_key_id = aws_kms_key.app_key.id
}

# AWS ACM Certificate
resource "aws_acm_certificate" "app_cert" {
  domain_name       = "app.example.com"
  validation_method = "DNS"
}

# AWS CloudHSM Cluster
resource "aws_cloudhsm_v2_cluster" "hsm_cluster" {
  hsm_type   = "hsm1.medium"
  subnet_ids = ["subnet-12345", "subnet-67890"]
}

# Azure Key Vault (using azurerm provider)
resource "azurerm_key_vault" "app_kv" {
  name                = "app-keyvault"
  location            = "East US"
  resource_group_name = "app-rg"
  tenant_id           = "tenant-id"
  sku_name            = "standard"
}

resource "azurerm_key_vault_key" "app_key" {
  name         = "app-key"
  key_vault_id = azurerm_key_vault.app_kv.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["encrypt", "decrypt", "sign", "verify"]
}

# GCP KMS Key Ring and Crypto Key
resource "google_kms_key_ring" "app_keyring" {
  name     = "app-keyring"
  location = "global"
}

resource "google_kms_crypto_key" "app_key" {
  name            = "app-key"
  key_ring        = google_kms_key_ring.app_keyring.id
  rotation_period = "7776000s"
}

# Generic KMS reference
resource "null_resource" "kms_config" {
  provisioner "local-exec" {
    command = "echo 'Configuring KMS key management service'"
  }
}