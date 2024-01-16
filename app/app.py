#!/usr/bin/env python3
import click
import oqs
import os
from tabulate import tabulate

def read_file_as_bytes(filepath):
    try:
        with open(filepath, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found at path: {filepath}")
    except IOError as e:
        raise IOError(f"Error reading file at {filepath}: {e}")


def gen_keypair(sigalg: str = 'Dilithium2') -> None:
    print(f"Generating key pair with {sigalg}...")
    try:
        with oqs.Signature(sigalg) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
    except ValueError as e:
        raise ValueError(f"Error in generating keypair with {sigalg}: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error during keypair generation: {e}")

    public_key_file = f"{sigalg}_public_key.pub"
    private_key_file = f"{sigalg}_private_key.key"
    try:
        with open(public_key_file, "wb") as pk_file:
            pk_file.write(public_key)
    except IOError as e:
        raise IOError(f"Failed to write public key to file: {public_key_file}, Error: {e}")
    try:
        with open(private_key_file, "wb") as pvk_file:
            pvk_file.write(private_key)
    except IOError as e:
        raise IOError(f"Failed to write private key to file: {private_key_file}, Error: {e}")
    print("Key pair generated")


def sign_file(file_to_sign_path: str, private_key_file_path: str, sigalg: str = 'Dilithium2') -> None:
    message = read_file_as_bytes(file_to_sign_path)
    private_key = read_file_as_bytes(private_key_file_path)
    filename_without_extension = os.path.splitext(os.path.basename(file_to_sign_path))[0]
    signature_file = f"signature_{filename_without_extension}_{sigalg}.sig"

    print(f"Signing {file_to_sign_path} file with {sigalg}...")
    try:
        with oqs.Signature(sigalg, private_key) as signer:
            signature = signer.sign(message)
    except ValueError as e:
        raise ValueError(f"Error in signing with {sigalg}: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error during signing: {e}")
    try:
        with open(signature_file, "wb") as file:
            file.write(signature)
    except IOError as e:
        raise IOError(f"Failed to write signature to file: {signature_file}, Error: {e}")
    print("Signed")


def verify_signature(signed_file, signature_file, public_key_file, sigalg='Dilithium2') -> bool:
    message = read_file_as_bytes(signed_file)
    public_key = read_file_as_bytes(public_key_file)
    signature = read_file_as_bytes(signature_file)

    try:
        with oqs.Signature(sigalg) as verifier:
            is_valid = verifier.verify(message, signature, public_key)
        return is_valid
    except ValueError as e:
        raise ValueError(f"Error in verification with {sigalg}: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error during signature verification: {e}")


@click.group(help="This tool allows you to perform post-quantum cryptographic signing")
def cli():
    pass


# WARNING: click replaces underscores('_') with hyphens('_')
@cli.command(help='Generate a public-private key pair using the specified algorithm')
@click.option('-a', '--algorithm', default='Dilithium2', help='The algorithm used to generate the key pair')
def generate_keypair(algorithm):
    gen_keypair(str(algorithm))


@cli.command(help="Sign the file using the specified algorithm and private key")
@click.argument('file_to_sign')
@click.argument('private_key')
@click.option('-a', '--algorithm', default='Dilithium2', help='The algorithm used in signature mechanism')
def sign(file_to_sign, private_key, algorithm):
    sign_file(file_to_sign, private_key, algorithm)


@cli.command(help="Verify the validity of the signature")
@click.argument('signed_file')
@click.argument('signature_file')
@click.argument('public_key')
@click.option('-a', '--algorithm', default='Dilithium2', help='The algorithm used in signature mechanism')
# @click.argument('')
def verify(signed_file, signature_file, public_key, algorithm):
    print(f'Is signature valid: {verify_signature(signed_file, signature_file, public_key, algorithm)}')


@cli.command(help="List available signature mechanisms")
def ls():
    mechanisms = list(enumerate(oqs.get_enabled_sig_mechanisms(), start=1))
    print(tabulate(mechanisms, headers=['Number', 'Mechanism']))


if __name__ == '__main__':
    cli()
