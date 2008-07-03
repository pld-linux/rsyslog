#
# Conditional build:
%bcond_without	gssapi		# Enable GSSAPI Kerberos 5 support
%bcond_without  mysql		# Enable MySql database support 
%bcond_without  pgsql		# Enable PostgreSQL database support
%bcond_without	snmp		# Enable SNMP support

Summary:	Linux system and kernel logger
Summary(de.UTF-8):	Linux-System- und Kerner-Logger
Summary(es.UTF-8):	Registrador de log del sistema linux
Summary(fr.UTF-8):	Le système Linux et le logger du noyau
Summary(pl.UTF-8):	Programy logujące zdarzenia w systemie i jądrze Linuksa
Summary(pt_BR.UTF-8):	Registrador de log do sistema linux
Summary(tr.UTF-8):	Linux sistem ve çekirdek kayıt süreci
Name:		rsyslog
Version:	3.16.2
Release:	0.1
License:	GPL v3
Group:		Daemons
Source0:	http://download.rsyslog.com/rsyslog/%{name}-%{version}.tar.gz
# Source0-md5:	568d0ad73a149974b9bcfcb9e64bfc0b
Source1:	%{name}.init
Source2:	%{name}.conf
Source3:	%{name}.sysconfig
URL:		http://www.rsyslog.com/
%{?with_gssapi:BuildRequires: krb5-devel}
%{?with_mysql:BuildRequires: mysql-devel}
%{?with_snmp:BuildRequires: net-snmp-devel}
%{?with_pgsql:BuildRequires: postgresql-devel}
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
Requires(triggerpostun):	sed >= 4.0
# for vservers we don't need klogd and syslog works without klogd
# (just it doesn't log kernel buffer into syslog)
# Requires:	klogd
Requires:	logrotate >= 3.2-3
Requires:	psmisc >= 20.1
Provides:	group(syslog)
Provides:	syslogdaemon
Provides:	user(syslog)
Obsoletes:	msyslog
Obsoletes:	sysklogd
Obsoletes:	syslog-ng
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%description
Rsyslog is an enhanced multi-threaded syslogd supporting, among
others, MySQL, syslog/tcp, RFC 3195, permitted sender lists, filtering
on any message part, and fine grain output format control. It is quite
compatible to stock sysklogd and can be used as a drop-in replacement.
Its advanced features make it suitable for enterprise-class,
encryption protected syslog relay chains while at the same time being
very easy to setup for the novice user.

%package klogd
Summary:	Linux kernel logger
Summary(de.UTF-8):	Linux-Kerner-Logger
Summary(pl.UTF-8):	Program logujący zdarzenia w jądrze Linuksa
Group:		Daemons
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
Provides:	group(syslog)
Provides:	user(syslog)
Obsoletes:	sysklogd

%description klogd
This is the Linux kernel logging program. It is run as a daemon
(background process) to log messages from kernel.

%description -l pl.UTF-8
Pakiet ten zawiera program, który jest uruchamiany jako demon i służy
do logowania komunikatów jądra Linuksa.

%package mysql
Summary:	MySQL support for rsyslog
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description mysql
The rsyslog-mysql package contains a dynamic shared object that will
add MySQL database support to rsyslog.

%package pgsql
Summary:	PostgresSQL support for rsyslog
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description pgsql
The rsyslog-pgsql package contains a dynamic shared object that will
add PostgreSQL database support to rsyslog.

%package gssapi
Summary:	GSSAPI authentication and encryption support for rsyslog
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description gssapi
The rsyslog-gssapi package contains the rsyslog plugins which support
GSSAPI authentication and secure connections. GSSAPI is commonly used
for Kerberos authentication.

%prep
%setup -q

%build
%configure \
%{?with_gssapi:--enable-gssapi-krb5} \
%{?with_mysql:--enable-mysql} \
%{?with_pgsql:--enable-pgsql} \
%{?with_snmp:--enable-snmp}

%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/{sysconfig,rc.d/init.d,logrotate.d} \
	$RPM_BUILD_ROOT{%{_sbindir},%{_mandir}/man{5,8},%{_bindir}} \
	$RPM_BUILD_ROOT/{dev,var/log}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/rsyslog
install %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/rsyslog.conf
install %{SOURCE3} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/rsyslog
install redhat/rsyslog.log $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/rsyslog

for n in debug kernel maillog messages secure syslog user spooler lpr daemon
do
	> $RPM_BUILD_ROOT/var/log/$n
done

%pre
%groupadd -P syslog -g 18 syslog
%useradd -P syslog -u 18 -g syslog -c "Syslog User" syslog
%addusertogroup syslog logs

%post
for n in /var/log/{cron,daemon,debug,kernel,lpr,maillog,messages,secure,spooler,syslog,user}; do
	if [ -f $n ]; then
		chown syslog:syslog $n
		continue
	else
		touch $n
		chmod 000 $n
		chown syslog:syslog $n
		chmod 640 $n
	fi
done

/sbin/chkconfig --add %{name}
%service syslog restart "%{name} daemon"
%service -q %{name}-klogd restart

%preun
if [ "$1" = "0" ]; then
	%service %{name} stop
	/sbin/chkconfig --del %{name}
fi

%postun
if [ "$1" = "0" ]; then
	%userremove syslog
	%groupremove syslog
fi

%pre klogd
%groupadd -P klogd -g 18 syslog
%useradd -P klogd -u 18 -g syslog -c "Syslog User" syslog
%addusertogroup syslog logs

%post klogd
/sbin/chkconfig --add %{name}-klogd
%service %{name}-klogd restart "kernel logger daemon"

%preun klogd
if [ "$1" = "0" ]; then
	%service %{name}-klogd stop
	/sbin/chkconfig --del %{name}-klogd
fi

%postun klogd
if [ "$1" = "0" ]; then
	%userremove syslog
	%groupremove syslog
fi

%triggerpostun -- inetutils-syslogd
/sbin/chkconfig --del syslog
/sbin/chkconfig --add syslog
if [ -f /etc/syslog.conf.rpmsave ]; then
	mv -f /etc/syslog.conf{,.rpmnew}
	mv -f /etc/syslog.conf{.rpmsave,}
	echo "Moved /etc/syslog.conf.rpmsave to /etc/syslog.conf"
	echo "Original file from package is available as /etc/syslog.conf.rpmnew"
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%doc AUTHORS ChangeLog NEWS README
%attr(640,root,syslog) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/rsyslog.conf
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/sysconfig/rsyslog
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/logrotate.d/rsyslog
%attr(754,root,root) /etc/rc.d/init.d/rsyslog
%attr(640,root,root) %ghost /var/log/*
%attr(755,root,root) %{_sbindir}/rsyslogd
%{_libdir}/rsyslog/omsnmp.so
%{_libdir}/rsyslog/imklog.so
%{_libdir}/rsyslog/immark.so
%{_libdir}/rsyslog/imtcp.so
%{_libdir}/rsyslog/imudp.so
%{_libdir}/rsyslog/imuxsock.so
%{_libdir}/rsyslog/lmgssutil.so
%{_libdir}/rsyslog/lmnet.so
%{_libdir}/rsyslog/lmregexp.so
%{_libdir}/rsyslog/lmtcpclt.so
%{_libdir}/rsyslog/lmtcpsrv.so
%{_libdir}/rsyslog/omtesting.so
%{_mandir}/man5/*
%{_mandir}/man8/*

%files klogd
%defattr(644,root,root,755)
#%attr(754,root,root) /etc/rc.d/init.d/klogd
#%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/sysconfig/klogd
#%attr(755,root,root) %{_sbindir}/klogd

%if %{with mysql}
%files mysql
%defattr(644,root,root,755)
%doc plugins/ommysql/createDB.sql
%{_libdir}/rsyslog/ommysql.so
%endif

%if %{with pgsql}
%files pgsql
%defattr(644,root,root,755)
%doc plugins/ompgsql/createDB.sql
%{_libdir}/rsyslog/ompgsql.so
%endif

%if %{with gssapi}
%files gssapi
%defattr(644,root,root,755)
%{_libdir}/rsyslog/imgssapi.so
%{_libdir}/rsyslog/omgssapi.so
%endif
