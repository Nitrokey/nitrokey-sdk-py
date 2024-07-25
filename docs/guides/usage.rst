Usage Guide
===========

.. contents:: :local:

The Nitrokey Python SDK currently supports Nitrokey 3 (:py:class:`nitrokey.nk3.NK3`) and Nitrokey Passkey (:py:class:`nitrokey.nkpk.NKPK`) devices.
Both devices are based on the same platform, Trussed, and therefore share the same base class :py:class:`nitrokey.trussed.TrussedDevice`.

Trussed devices can be rebooted into a bootloader mode that is used to apply firmware updates.
Devices in bootloader mode can be accessed using :py:class:`nitrokey.nk3.NK3Bootloader` and :py:class:`nitrokey.nkpk.NKPKBootloader` (base class :py:class:`nitrokey.trussed.TrussedBootloader`).

Listing and Opening Devices
---------------------------

Use the :py:meth:`nitrokey.trussed.TrussedDevice.list` function to list and open all connected devices::

    from nitrokey.nk3 import NK3
    from nitrokey.nkpk import NKPK

    print("Connected Nitrokey devices:")
    for device in NK3.list():
        print(f"- {device.name} at {device.path}")
    for device in NKPK.list():
        print(f"- {device.name} at {device.path}")

If you know the device path, use :py:meth:`nitrokey.trussed.TrussedDevice.open` instead::

    from nitrokey.nk3 import NK3
    from nitrokey.nkpk import NKPK

    path = "/dev/hidraw1"
    device = NK3.open(path)
    if device is not None:
        print(f"Found {device.name} at {path}")
    device = NKPK.open(path)
    if device is not None:
        print(f"Found {device.name} at {path}")

Similar functions are available for :py:class:`nitrokey.nk3.NK3Bootloader` and :py:class:`nitrokey.nkpk.NKPKBootloader`.
To list both normal and bootloader devices, use :py:meth:`nitrokey.nk3.list` and :py:meth:`nitrokey.nkpk.list`.

.. note::
   Currently, the devices returned by :py:meth:`nitrokey.trussed.TrussedDevice.list`, :py:meth:`nitrokey.nk3.list` and :py:meth:`nitrokey.nkpk.list` are only valid until the next call to any of the these functions.
   See `issue 31 <https://github.com/Nitrokey/nitrokey-sdk-py/issues/31>`_ for more information.

Using Applications
------------------

The Nitrokey Python SDK supports these applications for all Trussed devices:

* :py:class:`nitrokey.trussed.admin_app.AdminApp`: access device metadata and manage device configuration state
* :py:class:`nitrokey.trussed.provisioner_app.ProvisionerApp`: setup device in provisioner mode (only applicable for Hacker devices)

The Nitrokey 3 also provides these applications:

* :py:class:`nitrokey.nk3.secrets_app.SecretsApp`: securely store passwords and credentials

See the API reference for the application classes for more information.
