%define name python-cbtaxii
%define version 1.2
%define unmangled_version 1.2
%define release 2
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black Taxii Connector
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Bit9
Url: http://www.bit9.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller cb-taxii-connector.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
#!/bin/sh

mkdir -p /var/log/cb/integrations/cbtaxii/
touch /var/log/cb/integrations/cbtaxii/cbtaxii.log
mkdir -p /usr/share/cb/integrations/cbtaxii/feeds/

chown -R cb:cb /var/log/cb/integrations/cbtaxii
chown -R cb:cb /usr/share/cb/integrations/cbtaxii/feeds/
chmod +x /usr/share/cb/integrations/cbtaxii/cbtaxii


%files -f INSTALLED_FILES
%defattr(-,root,root)

%config
/etc/cb/integrations/cbtaxii/cbtaxii.conf.example

#%config(noreplace)
#/etc/cb/integrations/cbtaxii/cbtaxii.conf
