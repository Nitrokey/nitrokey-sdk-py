Name:           python3-nitrokey
Version:        0.2.4-rc.1
Release:        %autorelease
Summary:        Python SDK for Nitrokey devices

License:        Apache-2.0
URL:            https://github.com/Nitrokey/nitrokey-sdk-py
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz
# This patch is temporary until python3-protobuf >=5.26
Patch0:         protobuf.patch

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  %{py3_dist crcmod}
BuildRequires:  %{py3_dist cryptography}
BuildRequires:  %{py3_dist fido2}
BuildRequires:  %{py3_dist hidapi}
BuildRequires:  %{py3_dist poetry-core}
BuildRequires:  %{py3_dist protobuf}
BuildRequires:  %{py3_dist pyserial}
BuildRequires:  %{py3_dist semver}
BuildRequires:  %{py3_dist tlv8}

%description
The Nitrokey Python SDK can be used to use and configure Nitrokey devices.

%prep
%autosetup -p 1 -n nitrokey-sdk-py-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files nitrokey

%check

%files -f %{pyproject_files}
%license LICENSES/Apache-2.0.txt
%doc CHANGELOG.md
%doc README.md

%changelog
* Fri Nov 01 2024 Markus Merklinger <markus@nitrokey.com> - 0.2.3-1
- Add build dependency.
* Mon Oct 21 2024 Markus Merklinger <markus@nitrokey.com> - 0.2.0-1
- Initial package.
