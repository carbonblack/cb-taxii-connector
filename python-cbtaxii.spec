%define name python-cbtaxii
%define version 1.6.7
%define release 3
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define _build_id_links none

%define venv_location $VIRTUAL_ENV_PATH

Summary: VMware Carbon Black EDR Taxii Connector
Name: %{name}
Version: %{version}
Release: %{release}%{?dist}
Source0: %{name}-%{version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: VMware Carbon Black
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{version}

%build
%{venv_location}/bin/pyinstaller cb-taxii-connector.spec

%install
%{venv_location}/bin/python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
#rm -rf $RPM_BUILD_ROOT

%post
#!/bin/sh

mkdir -p /var/log/cb/integrations/cbtaxii/
touch /var/log/cb/integrations/cbtaxii/cbtaxii.log
mkdir -p /usr/share/cb/integrations/cbtaxii/feeds/

chown -R cb:cb /var/log/cb/integrations/cbtaxii
chown -R cb:cb /usr/share/cb/integrations/cbtaxii/feeds/
chmod +x /usr/share/cb/integrations/cbtaxii/cbtaxii
chmod -R u+r /usr/share/cb/integrations/cbtaxii/bin
chmod -R g+r /usr/share/cb/integrations/cbtaxii/bin
chmod -R o+r /usr/share/cb/integrations/cbtaxii/bin
chmod -R u+r /usr/share/cb/integrations/cbtaxii/bin/cbapi/
chmod -R g+r /usr/share/cb/integrations/cbtaxii/bin/cbapi/
chmod -R o+r /usr/share/cb/integrations/cbtaxii/bin/cbapi/

%files -f INSTALLED_FILES
%defattr(-,root,root)

%config
/etc/cb/integrations/cbtaxii/cbtaxii.conf.example

#%config(noreplace)
#/etc/cb/integrations/cbtaxii/cbtaxii.conf
