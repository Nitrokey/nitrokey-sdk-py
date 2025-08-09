Usage Guide
===========

.. contents:: :local:

The Nitrokey Python SDK currently supports Nitrokey 3 (:py:class:`nitrokey.nk3.NK3`) and Nitrokey Passkey (:py:class:`nitrokey.nkpk.NKPK`) devices.
Both devices are based on the same platform, Trussed, and therefore share the same base class :py:class:`nitrokey.trussed.TrussedDevice`.

Trussed devices can be rebooted into a bootloader mode that is used to apply firmware updates.
Devices in bootloader mode can be accessed using :py:class:`nitrokey.nk3.NK3Bootloader` and :py:class:`nitrokey.nkpk.NKPKBootloader` (base class :py:class:`nitrokey.trussed.TrussedBootloader`).

Listing and Opening Devices
---------------------------

Use the :py:func:`nitrokey.trussed.list` function to list and open all connected devices::

    import nitrokey.trussed

    print("Connected Nitrokey devices:")
    for device in nitrokey.trussed.list():
        print(f"- {device.name} at {device.path}")

If you know the device path, use :py:func:`nitrokey.trussed.open` instead::

    import nitrokey.trussed

    path = "/dev/hidraw1"
    device = nitrokey.trussed.open(path)
    if device is not None:
        print(f"Found {device.name} at {path}")
    else:
        print(f"No device found at {path}")

If you know the model you want to connect to, you can also use the ``list`` and ``open`` functions in the :py:mod:`nitrokey.nk3` or :py:mod:`nitrokey.nkpk` modules.
If you also know the type of the device, you can use the ``list`` and ``open`` methods of the :py:class:`nitrokey.nk3.NK3`, :py:class:`nitrokey.nkpk.NKPK`, :py:class:`nitrokey.nk3.NK3Bootloader` and :py:class:`nitrokey.nkpk.NKPKBootloader` classes.

Using Applications
------------------

The Nitrokey Python SDK supports these applications for all Trussed devices:

* :py:class:`nitrokey.trussed.admin_app.AdminApp`: access device metadata and manage device configuration state
* :py:class:`nitrokey.trussed.provisioner_app.ProvisionerApp`: setup device in provisioner mode (only applicable for Hacker devices)

The Nitrokey 3 also provides these applications:

* :py:class:`nitrokey.nk3.secrets_app.SecretsApp`: securely store passwords and credentials

See the API reference for the application classes for more information.
