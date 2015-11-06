# TODO
# - without gssapi still generates dep on heimdal-libs
#
# Conditional build:
%bcond_without	dbi		# database support via libdbi
%bcond_without	gssapi		# GSSAPI Kerberos 5 support
%bcond_without	mysql		# MySQL database support
%bcond_without	pgsql		# PostgreSQL database support
%bcond_without	snmp		# SNMP support

Summary:	Linux system and kernel logger
Summary(de.UTF-8):	Linux-System- und Kerner-Logger
Summary(es.UTF-8):	Registrador de log del sistema linux
Summary(fr.UTF-8):	Le système Linux et le logger du noyau
Summary(pl.UTF-8):	Programy logujące zdarzenia w systemie i jądrze Linuksa
Summary(pt_BR.UTF-8):	Registrador de log do sistema linux
Summary(tr.UTF-8):	Linux sistem ve çekirdek kayıt süreci
Name:		rsyslog
Version:	5.10.1
Release:	4
License:	GPL v3+
Group:		Daemons
Source0:	http://www.rsyslog.com/files/download/rsyslog/%{name}-%{version}.tar.gz
# Source0-md5:	a28c99e05888c977672db6e254694208
Source1:	%{name}.init
Source2:	%{name}.conf
Source3:	%{name}.sysconfig
Source4:	%{name}.logrotate
Patch0:		rsyslog-systemd.patch
URL:		http://www.rsyslog.com/
%{?with_gssapi:BuildRequires:	heimdal-devel}
BuildRequires:	libdbi-devel
%{?with_mysql:BuildRequires:	mysql-devel}
%{?with_snmp:BuildRequires:	net-snmp-devel}
BuildRequires:	pkgconfig
%{?with_pgsql:BuildRequires:	postgresql-devel}
BuildRequires:	libnet-devel
BuildRequires:	gnutls-devel
BuildRequires:	rpmbuild(macros) >= 1.626
Requires(post):	fileutils
Requires(post,preun):	/sbin/chkconfig
Requires(post,preun):	rc-scripts >= 0.2.0
Requires(postun):	/usr/sbin/groupdel
Requires(postun):	/usr/sbin/userdel
Requires(pre):	/bin/id
Requires(pre):	/usr/bin/getgid
Requires(pre):	/usr/lib/rpm/user_group.sh
Requires(pre):	/usr/sbin/groupadd
Requires(pre):	/usr/sbin/useradd
Requires(pre):	/usr/sbin/usermod
Requires(post,preun,postun):	systemd-units >= 38
Requires(triggerpostun):	sed >= 4.0
# for vservers we don't need klogd and syslog works without klogd
# (just it doesn't log kernel buffer into syslog)
# Requires:	klogd
Requires:	logrotate >= 3.2-3
Requires:	psmisc >= 20.1
Requires:	systemd-units >= 38
Provides:	group(syslog)
Provides:	service(klogd)
Provides:	service(syslog)
Provides:	syslogdaemon
Provides:	user(syslog)
Obsoletes:	msyslog
Obsoletes:	rsyslog-systemd
Obsoletes:	sysklogd
Obsoletes:	syslog-ng
Conflicts:	cronie < 1.5.0-3
Conflicts:	fcron < 3.1.2-5
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%description
Rsyslog is an enhanced multi-threaded syslogd supporting, among
others, MySQL, syslog/tcp, RFC 3195, permitted sender lists, filtering
on any message part, and fine grain output format control. It is quite
compatible to stock sysklogd and can be used as a drop-in replacement.
Its advanced features make it suitable for enterprise-class,
encryption protected syslog relay chains while at the same time being
very easy to setup for the novice user.

%description -l pl.UTF-8
rsyslog to zaawansowany, wielowątkowy syslogd obsługujący m.in.
MySQL-a, syslog/tcp, RFC 3195, listy dopuszczalnych nadawców,
filtrowanie po częściach komunikatów i szczegółową kontrolę formatu
wyjściowego. Jest w miarę kompatybilny ze zwykłym sysklogd i może być
używany jako jego zamiennik. Jego zaawansowane możliwości czynią go
odpowiednim do produkcyjnych, szyfrowanych łańcuchów przekazywania
logów, a jednocześnie jest przy tym łatwy do skonfigurowania dla
początkującego użytkownika.

%package mysql
Summary:	MySQL support for rsyslog
Summary(pl.UTF-8):	Obsługa MySQL-a do rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description mysql
The rsyslog-mysql package contains a dynamic shared object that will
add MySQL database support to rsyslog.

%description mysql -l pl.UTF-8
Pakiet rsyslog-mysql zawiera moduł dynamiczny dodający obsługę bazy
danych MySQL do rsysloga.

%package pgsql
Summary:	PostgresSQL support for rsyslog
Summary(pl.UTF-8):	Obsługa PostgreSQL-a dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description pgsql
The rsyslog-pgsql package contains a dynamic shared object that will
add PostgreSQL database support to rsyslog.

%description pgsql -l pl.UTF-8
Pakiet rsyslog-pgsql zawiera moduł dynamiczny dodający obsługę bazy
danych PostgreSQL do rsysloga.

%package gssapi
Summary:	GSSAPI authentication and encryption support for rsyslog
Summary(pl.UTF-8):	Obsługa uwierzytelniania GSSAPI i szyfrowania dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description gssapi
The rsyslog-gssapi package contains the rsyslog plugins which support
GSSAPI authentication and secure connections. GSSAPI is commonly used
for Kerberos authentication.

%description gssapi -l pl.UTF-8
Pakiet rsyslog-gssapi zawiera wtyczki rsysloga obsługujące
uwierzytelnianie GSSAPI i bezpieczne połączenia. GSSAPI jest
powszechnie używane do uwierzytelniania Kerberos.

%package dbi
Summary:	libdbi database support for rsyslog
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description dbi
This module supports a large number of database systems via
libdbi. Libdbi abstracts the database layer and provides drivers for
many systems. Drivers are available via the libdbi-drivers project.

%package udpspoof
Summary:	Provides the omudpspoof module
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description udpspoof
This module is similar to the regular UDP forwarder, but permits to
spoof the sender address. Also, it enables to circle through a number
of source ports.

%package snmp
Summary:	SNMP protocol support for rsyslog
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description snmp
The rsyslog-snmp package contains the rsyslog plugin that provides the
ability to send syslog messages as SNMPv1 and SNMPv2c traps.

%package gnutls
Summary:	TLS protocol support for rsyslog
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description gnutls
The rsyslog-gnutls package contains the rsyslog plugins that provide the
ability to receive syslog messages via upcoming syslog-transport-tls
IETF standard protocol.

%prep
%setup -q
%patch0 -p1

%build
%configure \
	--disable-silent-rules \
	--enable-gnutls \
	--enable-imdiag \
	--enable-imfile \
	--enable-impstats \
	--enable-imptcp \
	--enable-imtemplate \
	--enable-mail \
	--enable-mmsnmptrapd \
	--enable-omdbalerting \
	--enable-omprog \
	--enable-omstdout \
	--enable-omtemplate \
	--enable-omudpspoof \
	--enable-omuxsock \
	--enable-pmaixforwardedfrom \
	--enable-pmcisconames \
	--enable-pmlastmsg \
	--enable-pmrfc3164sd \
	--enable-pmsnare \
	--enable-smcustbindcdr \
	--enable-unlimited-select \
	%{?with_gssapi:--enable-gssapi-krb5} \
	%{?with_mysql:--enable-mysql} \
	%{?with_pgsql:--enable-pgsql} \
	%{?with_snmp:--enable-snmp} \
	%{?with_dbi:--enable-libdbi} \
	--with-systemdsystemunitdir=/lib/systemd/system

%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/{sysconfig,rc.d/init.d,logrotate.d,rsyslog.d} \
	$RPM_BUILD_ROOT{%{_sbindir},%{_mandir}/man{5,8},%{_bindir}} \
	$RPM_BUILD_ROOT/{dev,var/log}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install -p %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/rsyslog
cp -p %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/rsyslog.conf
cp -p %{SOURCE3} $RPM_BUILD_ROOT/etc/sysconfig/rsyslog
cp -p %{SOURCE4} $RPM_BUILD_ROOT/etc/logrotate.d/rsyslog

for n in cron daemon debug kernel lpr maillog messages secure spooler syslog user; do
	> $RPM_BUILD_ROOT/var/log/$n
done

%{__rm} $RPM_BUILD_ROOT%{_libdir}/rsyslog/*.la

%clean
rm -rf $RPM_BUILD_ROOT

%pre
%groupadd -P syslog -g 18 syslog
%useradd -P syslog -u 18 -g syslog -c "Syslog User" syslog
%addusertogroup syslog logs

%post
for n in /var/log/{cron,daemon,debug,kernel,lpr,maillog,messages,secure,spooler,syslog,user}; do
	if [ -f $n ]; then
		chown root:logs $n
		continue
	else
		touch $n
		chmod 000 $n
		chown root:logs $n
		chmod 640 $n
	fi
done

/sbin/chkconfig --add %{name}
%service rsyslog restart "%{name} daemon"

%systemd_post rsyslog.service
ln -sf /lib/systemd/system/rsyslog.service /etc/systemd/system/syslog.service || :

%preun
if [ "$1" = "0" ]; then
	%service %{name} stop
	/sbin/chkconfig --del %{name}
fi
%systemd_preun rsyslog.service

%postun
if [ "$1" = "0" ]; then
	%userremove syslog
	%groupremove syslog
fi
%systemd_reload

%triggerpostun -- %{name} < 5.8.6-4
%systemd_trigger rsyslog.service

%triggerpostun -- inetutils-syslogd
/sbin/chkconfig --del syslog
/sbin/chkconfig --add syslog
if [ -f /etc/syslog.conf.rpmsave ]; then
	mv -f /etc/syslog.conf{,.rpmnew}
	mv -f /etc/syslog.conf{.rpmsave,}
	echo "Moved /etc/syslog.conf.rpmsave to /etc/syslog.conf"
	echo "Original file from package is available as /etc/syslog.conf.rpmnew"
fi

%files
%defattr(644,root,root,755)
%doc AUTHORS ChangeLog NEWS README
%dir %{_sysconfdir}/rsyslog.d
%attr(640,root,syslog) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/rsyslog.conf
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/sysconfig/rsyslog
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/logrotate.d/rsyslog
%attr(754,root,root) /etc/rc.d/init.d/rsyslog
%attr(640,root,logs) %ghost /var/log/*
/lib/systemd/system/rsyslog.service
%attr(755,root,root) %{_sbindir}/rsyslogd
%dir %{_libdir}/rsyslog
%attr(755,root,root) %{_libdir}/rsyslog/imfile.so
%attr(755,root,root) %{_libdir}/rsyslog/imklog.so
%attr(755,root,root) %{_libdir}/rsyslog/immark.so
%attr(755,root,root) %{_libdir}/rsyslog/imtcp.so
%attr(755,root,root) %{_libdir}/rsyslog/imudp.so
%attr(755,root,root) %{_libdir}/rsyslog/imuxsock.so
%attr(755,root,root) %{_libdir}/rsyslog/lmnet.so
%attr(755,root,root) %{_libdir}/rsyslog/lmnetstrms.so
%attr(755,root,root) %{_libdir}/rsyslog/lmnsd_ptcp.so
%attr(755,root,root) %{_libdir}/rsyslog/lmregexp.so
%attr(755,root,root) %{_libdir}/rsyslog/lmstrmsrv.so
%attr(755,root,root) %{_libdir}/rsyslog/lmtcpclt.so
%attr(755,root,root) %{_libdir}/rsyslog/lmtcpsrv.so
%attr(755,root,root) %{_libdir}/rsyslog/lmzlibw.so
%attr(755,root,root) %{_libdir}/rsyslog/omruleset.so
%attr(755,root,root) %{_libdir}/rsyslog/omtesting.so
%attr(755,root,root) %{_libdir}/rsyslog/imdiag.so
%attr(755,root,root) %{_libdir}/rsyslog/impstats.so
%attr(755,root,root) %{_libdir}/rsyslog/imptcp.so
%attr(755,root,root) %{_libdir}/rsyslog/imtemplate.so
%attr(755,root,root) %{_libdir}/rsyslog/mmsnmptrapd.so
%attr(755,root,root) %{_libdir}/rsyslog/omdbalerting.so
%attr(755,root,root) %{_libdir}/rsyslog/ommail.so
%attr(755,root,root) %{_libdir}/rsyslog/omprog.so
%attr(755,root,root) %{_libdir}/rsyslog/omstdout.so
%attr(755,root,root) %{_libdir}/rsyslog/omtemplate.so
%attr(755,root,root) %{_libdir}/rsyslog/omuxsock.so
%attr(755,root,root) %{_libdir}/rsyslog/pmaixforwardedfrom.so
%attr(755,root,root) %{_libdir}/rsyslog/pmcisconames.so
%attr(755,root,root) %{_libdir}/rsyslog/pmlastmsg.so
%attr(755,root,root) %{_libdir}/rsyslog/pmrfc3164sd.so
%attr(755,root,root) %{_libdir}/rsyslog/pmsnare.so
%attr(755,root,root) %{_libdir}/rsyslog/sm_cust_bindcdr.so
%{_mandir}/man5/*
%{_mandir}/man8/*

%if %{with mysql}
%files mysql
%defattr(644,root,root,755)
%doc plugins/ommysql/createDB.sql
%attr(755,root,root) %{_libdir}/rsyslog/ommysql.so
%endif

%if %{with pgsql}
%files pgsql
%defattr(644,root,root,755)
%doc plugins/ompgsql/createDB.sql
%attr(755,root,root) %{_libdir}/rsyslog/ompgsql.so
%endif

%if %{with gssapi}
%files gssapi
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/imgssapi.so
%attr(755,root,root) %{_libdir}/rsyslog/lmgssutil.so
%attr(755,root,root) %{_libdir}/rsyslog/omgssapi.so
%endif

%if %{with dbi}
%files dbi
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omlibdbi.so
%endif

%files udpspoof
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omudpspoof.so

%if %{with snmp}
%files snmp
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omsnmp.so
%endif

%files gnutls
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/lmnsd_gtls.so
