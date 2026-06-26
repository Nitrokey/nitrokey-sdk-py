nitrokey.trussed
================

.. automodule:: nitrokey.trussed

.. rubric:: Submodules

.. toctree::
   :maxdepth: 1

   nitrokey.trussed.admin_app
   nitrokey.trussed.provisioner_app
   nitrokey.trussed.updates


Accessing Trussed Devices
-------------------------

.. autofunction:: nitrokey.trussed.list

.. autofunction:: nitrokey.trussed.open

.. autofunction:: nitrokey.trussed.recommended_transport

.. autoclass:: nitrokey.trussed.Transport
   :members:
   :undoc-members:

Trussed Device Objects
----------------------

.. autoclass:: nitrokey.trussed.TrussedBase
   :members:
   :undoc-members:

.. autoclass:: nitrokey.trussed.TrussedDevice
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: nitrokey.trussed.TrussedBootloader
   :members:
   :undoc-members:
   :show-inheritance:

Error Codes
-----------

.. autoclass:: nitrokey.trussed.CcidErrorCode
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: nitrokey.trussed.CtapErrorCode
   :members:
   :undoc-members:
   :show-inheritance:

Update Container Objects
------------------------

.. autofunction:: nitrokey.trussed.parse_firmware_image

.. autoclass:: nitrokey.trussed.FirmwareContainer
   :members:
   :undoc-members:

.. autoclass:: nitrokey.trussed.FirmwareMetadata
   :members:
   :undoc-members:

.. autoclass:: nitrokey.trussed.Variant
   :members:
   :undoc-members:
   :show-inheritance:

Utility Objects
---------------

.. autoclass:: nitrokey.trussed.App
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: nitrokey.trussed.Fido2Certs
   :members:
   :undoc-members:

.. autoclass:: nitrokey.trussed.Model
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: nitrokey.trussed.Uuid
   :members:
   :undoc-members:

.. autoclass:: nitrokey.trussed.Version
   :members:
   :undoc-members:

Trussed Exceptions
------------------

.. autoclass:: nitrokey.trussed.TrussedException
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: nitrokey.trussed.ConnectionError
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: nitrokey.trussed.DeviceError
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: nitrokey.trussed.TimeoutException
   :members:
   :undoc-members:
   :show-inheritance:

Constants
---------

.. autodata:: nitrokey.trussed.DEFAULT_TRANSPORT

   The default transport that is used if no explicit transport is set.

   Currently, this is CTAPHID as this is the only transport that supports all features.  See also
   the :py:func:`recommended_transport` function that provides a sensible default for most applications.

.. autodata:: nitrokey.trussed.HAS_CCID_SUPPORT
