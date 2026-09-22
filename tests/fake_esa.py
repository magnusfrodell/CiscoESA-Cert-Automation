#!/usr/bin/env python3
"""
fake_esa.py - a minimal imitation of the AsyncOS CLI dialogue that esa_deploy.py
drives, used by the test suite. It is deliberately small and only implements
what the deploy-hook touches: login, clustermode, certconfig > certificate >
import, commit and exit. Scenario flags make it misbehave in the ways the
script is expected to handle.

Copyright (c) 2026 Cisco and/or its affiliates.
Licensed under the Cisco Sample Code License, Version 1.1 - see LICENSE.
"""

from __future__ import annotations

import argparse
import sys

try:
    import termios
except ImportError:  # pragma: no cover
    termios = None  # type: ignore[assignment]

FQDN_QUESTION = ("Do you want to check if Common Name or SAN:dNSName or both are in Fully\n"
                 "Qualified Domain Name(FQDN) format ? [N]> ")


class FakeEsa:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.hostname = "esa.test"
        self.prompt = f"{self.hostname} (Cluster c1)> " if args.cluster else f"{self.hostname}> "
        self.profiles = {"lets_encrypt_mail"} if args.existing_profile else set()
        self.pending = False

    # ------------------------------------------------------------------ I/O

    def out(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    def readline(self, secret: bool = False) -> str:
        if secret and termios is not None and sys.stdin.isatty():
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            new = list(old)
            new[3] = new[3] & ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            try:
                line = sys.stdin.readline()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            self.out("\n")
        else:
            line = sys.stdin.readline()
        if not line:
            sys.exit(0)
        return line.rstrip("\r\n")

    # ------------------------------------------------------------------ main loop

    def run(self) -> None:
        if self.args.password_login:
            self.out("Password: ")
            if self.readline(secret=True) != self.args.login_password:
                self.out("Permission denied, please try again.\nPassword: ")
                self.readline(secret=True)
                self.out("Permission denied (keyboard-interactive,password).\n")
                sys.exit(255)
        self.out("Last login: Tue Sep 22 09:00:00 2026 from 192.0.2.10\n")
        self.out("AsyncOS 16.0.3 for Cisco C100V build 025\n")
        self.out("Welcome to the Cisco C100V Email Security Virtual Appliance\n")
        while True:
            self.out("\n" + self.prompt)
            command = self.readline().strip()
            if command == "":
                continue
            if command == "certconfig":
                self.certconfig()
            elif command == "commit":
                self.commit()
            elif command.startswith("clustermode"):
                self.clustermode(command)
            elif command in ("exit", "quit"):
                if self.args.exit_question and self.pending:
                    self.out("There are uncommitted changes. Do you want to commit before exiting? [N]> ")
                    self.readline()
                self.out("\nConnection closed.\n")
                sys.exit(0)
            else:
                self.out(f"\nUnknown command '{command}'.\n")

    # ------------------------------------------------------------------ clustermode

    def clustermode(self, command: str) -> None:
        parts = command.split()
        if self.args.clustermode_menu or len(parts) == 1:
            self.out("\nChoose the mode to modify:\n1. Cluster\n2. Group\n3. Machine\n[1]> ")
            choice = self.readline().strip() or "1"
            if choice == "3":
                self.out("\nChoose the machine to modify:\n1. esa.test\n2. esa2.test\n[1]> ")
                machine = self.readline().strip() or "1"
                name = {"1": "esa.test", "2": "esa2.test"}.get(machine, "esa.test")
                self.prompt = f"{self.hostname} (Machine {name})> "
            elif choice == "2":
                self.prompt = f"{self.hostname} (Group g1)> "
            else:
                self.prompt = f"{self.hostname} (Cluster c1)> "
            return
        level = parts[1]
        name = parts[2] if len(parts) > 2 else "esa.test"
        if level == "machine":
            self.prompt = f"{self.hostname} (Machine {name})> "
        elif level == "group":
            self.prompt = f"{self.hostname} (Group {name})> "
        else:
            self.prompt = f"{self.hostname} (Cluster c1)> "

    # ------------------------------------------------------------------ certconfig

    def certconfig(self) -> None:
        if self.args.cluster_level_question:
            self.out("\nDo you want to make changes at the cluster level, group level or machine level? [C]> ")
            self.readline()
        while True:
            self.out("\nChoose the operation you want to perform:\n"
                     "- CERTIFICATE - Import, Create a request, Edit or Remove Certificate Profiles\n"
                     "- CERTAUTHORITY - Manage System and Customer CAs\n"
                     "- CRL - Manage Certificate Revocation Lists\n"
                     "[]> ")
            choice = self.readline().strip().lower()
            if choice == "":
                return
            if choice == "certificate":
                self.certificate_menu()
            else:
                self.out("\nInvalid entry.\n")

    def certificate_menu(self) -> None:
        while True:
            self.out("\nList of Certificates\n"
                     "Name                 Common Name          Issued By            Status  Remaining\n"
                     "-------------------- -------------------- -------------------- ------- ---------\n")
            for profile in sorted(self.profiles):
                self.out(f"{profile:<20} mail.example.com     R11                  Active  60 days\n")
            self.out("\nChoose the operation you want to perform:\n"
                     "- IMPORT - Import a certificate from a local PKCS#12 file\n"
                     "- PASTE - Paste a certificate and private key\n"
                     "- NEW - Create a self-signed certificate and CSR\n"
                     "- EDIT - Update certificate or view the signing request\n"
                     "- DELETE - Delete a certificate\n"
                     "- PRINT - Display a certificate\n"
                     "[]> ")
            choice = self.readline().strip().lower()
            if choice == "":
                return
            if choice == "import":
                self.import_profile()
            else:
                self.out("\nInvalid entry.\n")

    def import_profile(self) -> None:
        self.out("\nEnter a name for this certificate profile:\n> ")
        name = self.readline().strip()
        if not name or any(c in name for c in "!@#$%^&*()+= "):
            self.out("\nSymbols are not allowed in the profile name.\n")
            return
        if name in self.profiles:
            self.out(f'\nCertificate profile "{name}" already exists. Do you want to\n'
                     "overwrite with this new one? [N]> ")
            if self.readline().strip().upper() != "Y":
                return
        self.out(f'\nEnter the name of the file on machine "{self.hostname}" to import:\n[]> ')
        filename = self.readline().strip()
        if self.args.missing_file:
            self.out(f"\nError: file '{filename}' does not exist.\n")
            return
        if self.args.fqdn_before:
            self.out("\n" + FQDN_QUESTION)
            self.readline()
        self.out("\nEnter pass phrase for PKCS#12 file: ")
        passphrase = self.readline(secret=True)
        if passphrase != self.args.pfx_password:
            self.out("\nInvalid pass phrase or corrupt PKCS#12 file.\n")
            return
        if self.args.fqdn_after:
            self.out("\n" + FQDN_QUESTION)
            self.readline()
        self.profiles.add(name)
        self.pending = not self.args.no_data_commit
        self.out(f'\nCertificate profile "{name}" imported.\n')

    # ------------------------------------------------------------------ commit

    def commit(self) -> None:
        if not self.pending:
            self.out("\nThere is no data to commit.\n")
            return
        self.out("\nPlease enter some comments describing your changes:\n[]> ")
        self.readline()
        if not self.args.no_rollback_question:
            self.out("\nDo you want to save the current configuration for rollback? [Y]> ")
            self.readline()
        self.out("\nChanges committed: Tue Sep 22 09:05:00 2026 CEST\n")
        self.pending = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fake AsyncOS CLI for tests")
    parser.add_argument("--pfx-password", default="pfxsecret")
    parser.add_argument("--existing-profile", action="store_true")
    parser.add_argument("--fqdn-before", action="store_true")
    parser.add_argument("--fqdn-after", action="store_true")
    parser.add_argument("--no-data-commit", action="store_true")
    parser.add_argument("--no-rollback-question", action="store_true")
    parser.add_argument("--missing-file", action="store_true")
    parser.add_argument("--password-login", action="store_true")
    parser.add_argument("--login-password", default="adminpw")
    parser.add_argument("--cluster", action="store_true")
    parser.add_argument("--clustermode-menu", action="store_true")
    parser.add_argument("--cluster-level-question", action="store_true")
    parser.add_argument("--exit-question", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    FakeEsa(parse_args()).run()
