"""Require signed receipt shape on every publication path; retain old evidence.

ECDSA verification against independently installed keys is performed by the
application on writes AND every use/exposure. SQL enforces immutable statements
and signature presence, not cryptographic verification. DB writers remain trusted.
Unsigned pre-fix records are retained but fail application verification; never
silently backfill signatures, ownership, addresses or financial journals.
"""

from importlib import import_module

from django.db import migrations


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    old = import_module("custody.migrations.0030_mpc_child_ownership_guards").FORWARD
    import re

    functions = re.findall(r"CREATE FUNCTION .*?\$\$ LANGUAGE plpgsql;", old, re.S)
    hd, account = functions[:2]
    hd = hd.replace(
        "IF receipt IS DISTINCT FROM", "IF receipt - 'signer_signature' IS DISTINCT FROM"
    )
    hd = hd.replace(
        "'durable', true) THEN",
        "'durable', true) OR coalesce(receipt ->> 'signer_signature', '') "
        "!~ '^[0-9a-f]{16,160}$' THEN",
    )
    account = account.replace(
        "NEW.evidence -> 'participant_agreement' -> i IS DISTINCT FROM",
        "(NEW.evidence -> 'participant_agreement' -> i) - 'signer_signature' IS DISTINCT FROM",
    )
    account = account.replace(
        "true) THEN",
        "true) OR coalesce(NEW.evidence -> 'participant_agreement' -> i "
        "->> 'signer_signature', '') !~ '^[0-9a-f]{16,160}$' "
        "OR coalesce(h.evidence -> 'participant_agreement' -> i "
        "->> 'signer_signature', '') !~ '^[0-9a-f]{16,160}$' THEN",
    )
    for function in (hd, account):
        schema_editor.execute(
            function.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"), params=None
        )


def uninstall(apps, schema_editor):
    if (
        apps.get_model("custody", "MpcHdRootEvidence").objects.exists()
        or apps.get_model("custody", "MpcCustodyAccount").objects.exists()
    ):
        raise RuntimeError("cannot downgrade independent signer-origin publication enforcement")
    if schema_editor.connection.vendor == "postgresql":
        import re

        old = import_module("custody.migrations.0030_mpc_child_ownership_guards").FORWARD
        for function in re.findall(r"CREATE FUNCTION .*?\$\$ LANGUAGE plpgsql;", old, re.S)[:2]:
            schema_editor.execute(
                function.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"), params=None
            )


class Migration(migrations.Migration):
    dependencies = [("custody", "0031_original_custody_child_authorization")]
    operations = [migrations.RunPython(install, uninstall)]
