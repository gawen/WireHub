%define         instdir         /opt/wh
%define         wireguard_ver   0.0.20190406

Name:           wirehub
Version:        0.0.20190129
Release:        1%{?dist}
Summary:        Decentralized, peer-to-peer and secure overlay networks
License:        GPLv2+
URL:            https://github.com/Gawen/WireHub
Source0:        https://github.com/Gawen/WireHub/archive/%{version}.tar.gz
Source1:        https://git.zx2c4.com/WireGuard/snapshot/WireGuard-%{wireguard_ver}.tar.xz
Source2:	wirehub@.service
Source3:	wirehub.sysconfig

BuildRequires:	systemd
# https://dl.iuscommunity.org/pub/ius/stable/CentOS/7/x86_64/repoview/lua53u-devel.html
BuildRequires:  lua53u-devel
BuildRequires:  miniupnpc-devel
BuildRequires:  libsodium-devel
BuildRequires:  libpcap-devel >= 1.9.0
BuildRequires:  xz
Requires:       wireguard = %{wireguard_ver}

%{!?lua_version: %global lua_version 5.3}
# for compiled modules
%{!?lua_libdir: %global lua_libdir %{_libdir}/lua/%{lua_version}}
# for arch-independent modules
%{!?lua_pkgdir: %global lua_pkgdir %{_datadir}/lua/%{lua_version}}

%global lualib lua-5.3

%description
%{summary}

%prep
%setup -q -n WireHub-%{version}

unxz -c %{SOURCE1} | tar -C deps/WireGuard --transform 's:^WireGuard-%{wireguard_ver}::' -x -f -

%build
CFLAGS="%{optflags} -DWH_ENABLE_MINIUPNPC -D_BSD_SOURCE -std=gnu99 -Wall -fPIC -I$(pwd)/include $(pkg-config --cflags %{lualib})"
LDFLAGS="%{build_ldflags} $(pkg-config --libs %{lualib}) -lsodium -lpthread -lpcap -lminiupnpc"

%make_build MINIMAL_CFLAGS="${DEFS} ${CFLAGS}" LDFLAGS="${LDFLAGS}"

%install
mkdir -p \
  %{buildroot}%{instdir} \
  %{buildroot}%{instdir}/tools \
  %{buildroot}%{lua_libdir} \
  %{buildroot}%{_bindir}

printf "#!/usr/bin/env bash\nexport LUA_PATH=/opt/wh/?.lua\nexec lua-5.3 %{instdir}/tools/cli.lua \$@\n" >> %{buildroot}%{_bindir}/wh
chmod 0755 %{buildroot}%{_bindir}/wh

%{__cp} src/*.lua       %{buildroot}%{instdir}
%{__cp} src/tools/*.lua %{buildroot}%{instdir}/tools
%{__cp} .obj/*.so       %{buildroot}%{lua_libdir}

install -Dpm 0640 config/public %{buildroot}%{_sysconfdir}/wirehub/config
install -Dpm 0644 %{SOURCE2} %{buildroot}%{_unitdir}/wirehub@.service

%post
if ! test -f /etc/wirehub/config.sk
then
  wh genkey | tee /etc/wirehub/config.sk | wh pubkey | tee /etc/wirehub/config.k
  chmod 0600 /etc/wirehub/config.sk
  chmod 0644 /etc/wirehub/config.k
fi

%systemd_post wirehub@.service
exit 0

%preun
%systemd_preun wirehub@.service
exit 0

%postun
%systemd_postun wildfly@.service
exit 0

%clean
rm -rf .obj %{buildroot}

%files
%defattr(-,root,root,-)
%doc README.md LICENSE
%{_bindir}/wh
%{instdir}/*.lua
%{instdir}/tools/*.lua
%{lua_libdir}/*.so
%{_unitdir}/wirehub@.service
%config(noreplace) %{_sysconfdir}/wirehub/config

%changelog
* Wed May 22 2019 fuero <fuerob@gmail.com> - 0.0.20190129-1
- initial packaging
