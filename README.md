# JWT Generator

A Python tool for generating JWT tokens using ES256 (ECDSA with P-256 curve) signatures. The tool automatically manages cryptographic key pairs and generates signed JWT tokens from JSON payloads.

## Installation

### Prerequisites

- Python 3.8 or higher
- [Hatch](https://hatch.pypa.io/) (install with `pip install hatch`)

### Install Dependencies

```bash
# Install in development mode
hatch shell
```

## Usage

### Basic Usage

```bash
# Generate JWT from JSON payload file
hatch run jwt-gen path/to/payload.json

# Generate JWT with Authorization header format
hatch run jwt-gen --header path/to/payload.json
```

### Key Management

On first run, the tool automatically generates:
- `private.key` - ES256 private key (keep secure!)
- `public.key` - ES256 public key (safe to share)

These files are created in the current working directory and reused for subsequent JWT generation.

## JWT Structure

The generated tokens use:
- **Algorithm**: ES256 (ECDSA using P-256 curve and SHA-256)
- **Header**: `{"alg": "ES256", "typ": "JWT"}`
- **Payload**: Content from your JSON file
- **Signature**: ECDSA signature using the generated private key

## Development

### Building

```bash
# Build wheel
hatch build

# Install built wheel
pip install dist/*.whl
```

## License

This project is licensed under the MIT License - see the [LICENSE-MIT](LICENSE-MIT) file for details.