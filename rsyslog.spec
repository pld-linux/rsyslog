# TODO
# - without gssapi still generates dep on heimdal-libs
# --enable-omhdfs? (BR: hdfs.h or hadoop/hdfs.h)
#
# Conditional build:
%bcond_without	amqp		# AMQP (Qpid Proton) output support
%bcond_without	curl		# clickhouse, elasticsearch, fmhttp, imdocker, and omhttpfs support vis curl
%bcond_without	dbi		# database support via libdbi
%bcond_without	grok		# mmgrok support
%bcond_without	gssapi		# GSSAPI Kerberos 5 support
%bcond_without	kafka		# Kafka output support
%bcond_without	ksi		# log file signing support (via GuardTime KSI LS12)
%bcond_without	lognorm		# normalization modules
%bcond_without	maxminddb	# MaxmindDB dblookup support
%bcond_without	mongodb		# MongoDB output support
%bcond_without	mysql		# MySQL database support
%bcond_with	openssl		# mmrfc5424addhmac module
%bcond_without	pgsql		# PostgreSQL database support
%bcond_without	rabbitmq	# RammitMQ support
%bcond_without	redis		# REDIS output support via hiredis
%bcond_without	relp		# RELP input/output support
%bcond_without	rfc3195		# RFC 3195 input support
%bcond_without	snmp		# SNMP support
%bcond_with	tcl		# Tcl output support [broken tcl linking]
%bcond_without	zeromq		# 0MQ input/output support via czmq
%bcond_without	systemd		# systemd integration and journal (input/output) support

Summary:	Linux system and kernel logger
Summary(de.UTF-8):	Linux-System- und Kerner-Logger
Summary(es.UTF-8):	Registrador de log del sistema linux
Summary(fr.UTF-8):	Le système Linux et le logger du noyau
Summary(pl.UTF-8):	Programy logujące zdarzenia w systemie i jądrze Linuksa
Summary(pt_BR.UTF-8):	Registrador de log do sistema linux
Summary(tr.UTF-8):	Linux sistem ve çekirdek kayıt süreci
Name:		rsyslog
Version:	8.2402.0
Release:	1
License:	GPL v3+
Group:		Daemons
#Source0Download: https://www.rsyslog.com/downloads/download-v8-stable/
Source0:	https://www.rsyslog.com/files/download/rsyslog/%{name}-%{version}.tar.gz
# Source0-md5:	422b7d457f184134a872a5a519d3884e
Source1:	%{name}.init
Source2:	%{name}.conf
Source3:	%{name}.sysconfig
Source4:	%{name}.logrotate
Source5:	%{name}.service
Patch0:		%{name}-tirpc.patch
URL:		https://www.rsyslog.com/
BuildRequires:	autoconf >= 2.61
BuildRequires:	automake
%{?with_zeromq:BuildRequires:	czmq-devel >= 3.0.2}
%{?with_grok:BuildRequires:	glib2-devel >= 2.0}
BuildRequires:	gnutls-devel >= 1.4.0
%{?with_grok:BuildRequires:	grok-devel}
%{?with_gssapi:BuildRequires:	heimdal-devel}
%{?with_redis:BuildRequires:	hiredis-devel >= 0.10.1}
BuildRequires:	libdbi-devel
BuildRequires:	libestr-devel >= 0.1.9
BuildRequires:	libfastjson-devel >= 0.99.8
BuildRequires:	libgcrypt-devel
%{?with_ksi:BuildRequires:	libksi-devel >= 3.19.0}
%{?with_rfc3195:BuildRequires:	liblogging-rfc3195-devel >= 1.0.1}
BuildRequires:	liblogging-stdlog-devel >= 1.0.3
%{?with_lognorm:BuildRequires:	liblognorm-devel >= 2.0.3}
%{?with_maxminddb:BuildRequires:	libmaxminddb-devel}
BuildRequires:	libnet-devel >= 1:1.1
%{?with_kafka:BuildRequires:	librdkafka-devel >= 0.9.1}
%{?with_relp:BuildRequires:	librelp-devel >= 1.2.14}
BuildRequires:	libtirpc-devel
BuildRequires:	libtool
BuildRequires:	libuuid-devel
%{?with_mongodb:BuildRequires:	mongo-c-driver-devel >= 1.0}
%{?with_mysql:BuildRequires:	mysql-devel}
%{?with_snmp:BuildRequires:	net-snmp-devel}
%{?with_openssl:BuildRequires:	openssl-devel >= 0.9.7}
%{?with_amqp:BuildRequires:	qpid-proton-c-devel >= 0.9}
BuildRequires:	pkgconfig
%{?with_pgsql:BuildRequires:	postgresql-devel}
%{?with_rabbitmq:BuildRequires:	rabbitmq-c-devel >= 0.2.0}
BuildRequires:	rpmbuild(macros) >= 1.626
%{?with_systemd:BuildRequires:	systemd-devel >= 1:234}
%{?with_tcl:BuildRequires:	tcl-devel}
BuildRequires:	xxHash-devel
BuildRequires:	zlib-devel
Requires(post):	fileutils
Requires(post):	sed >= 4.0
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
# for vservers we don't need klogd and syslog works without klogd
# (just it doesn't log kernel buffer into syslog)
# Requires:	klogd
Requires:	libestr >= 0.1.9
Requires:	libfastjson >= 0.99.8
Requires:	liblogging-stdlog >= 1.0.3
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

%package http
Summary:	HTTP support modules for rsyslog
Summary(pl.UTF-8):	Moduły obsługujące HTTP dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description http
HTTP support modules for rsyslog: http function module, docker input
module, clickhouse output module, elasticsearch output module, http
output module and httpfs output module.

%description http -l pl.UTF-8
Moduły obsługujące HTTP dla rsysloga: moduł funkcji http, moduł
wejściowy docker, moduł wyjściowy clickhouse, moduł wyjściowy
elasticsearch i moduł wyjściowy http i moduł wyjściowy httpfs.

%package czmq
Summary:	0MQ input/output support for rsyslog
Summary(pl.UTF-8):	Obsługa wejścia/wyjścia 0MQ dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	czmq >= 3.0.2

%description czmq
0MQ input/output support for rsyslog.

%description czmq -l pl.UTF-8
Obsługa wejścia/wyjścia 0MQ dla rsysloga.

%package kafka
Summary:	Kafka input/output support for rsyslog
Summary(pl.UTF-8):	Obsługa wejścia/wyjścia Kafka dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	librdkafka >= 0.9.1

%description kafka
Kafka input/output support for rsyslog.

%description kafka -l pl.UTF-8
Obsługa wejścia/wyjścia Kafka dla rsysloga.

%package relp
Summary:	RELP input/output support for rsyslog
Summary(pl.UTF-8):	Obsługa wejścia/wyjścia RELP dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	librelp >= 1.2.14

%description relp
RELP input/output support for rsyslog.

%description relp -l pl.UTF-8
Obsługa wejścia/wyjścia RELP dla rsysloga.

%package normalize
Summary:	Normalization plugins for rsyslog
Summary(pl.UTF-8):	Wtyczki normalizujące dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	liblognorm >= 2.0.3

%description normalize
rsyslog message modification and parser modules for parsing and
normalizing incoming messages with liblognorm.

%description normalize -l pl.UTF-8
Moduły rsysloga: modyfikujący komuynikaty i analizujący do analizy i
normalizowania przychodzących komunikatów przy użyciu biblioteki
liblognorm.

%package rfc3195
Summary:	RFC 3195 input support for rsyslog
Summary(pl.UTF-8):	Obsługa wejścia RFC 3195 dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	liblogging-rfc3195 >= 1.0.1

%description rfc3195
RFC 3195 input support for rsyslog.

%description rfc3195 -l pl.UTF-8
Obsługa wejścia RFC 3195 dla rsysloga.

%package gnutls
Summary:	TLS protocol support for rsyslog
Summary(pl.UTF-8):	Obsługa protokołu TLS dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	gnutls-libs >= 1.4.0

%description gnutls
The rsyslog-gnutls package contains the rsyslog plugin that provide
the ability to receive syslog messages via upcoming
syslog-transport-tls IETF standard protocol.

%description gnutls -l pl.UTF-8
Ten pakiet zawiera wtyczkę rsysloga zapewniającą możliwośc odbierania
komunikatów sysloga poprzez protokół nadchodzącego standardu IETF
syslog-transport-tls.

%package ksi
Summary:	GuardTime KSI-LS12 signing support for rsyslog
Summary(pl.UTF-8):	Obsługa podpisów GuardTime KSI-LS12 dl rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	libksi-devel >= 3.19.0

%description ksi
GuardTime KSI-LS12 signing support for rsyslog.

%description ksi -l pl.UTF-8
Obsługa podpisów GuardTime KSI-LS12 dl rsysloga.

%package mmdblookup
Summary:	Maxmind DB lookup module for rsyslog
Summary(pl.UTF-8):	Moduł wyszukujący w bazie Maxmind DB dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description mmdblookup
Maxmind DB lookup module for rsyslog.

%description mmdblookup -l pl.UTF-8
Moduł wyszukujący w bazie Maxmind DB dla rsysloga.

%package mmgrok
Summary:	Grok Message Modify plugin for rsyslog
Summary(pl.UTF-8):	Wtyczka modyfikująca komunikaty Grok dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description mmgrok
Grok Message Modify plugin for rsyslog. Messages are parsed into a
structured JSON data.

%description mmgrok -l pl.UTF-8
Wtyczka modyfikująca komunikaty Grok dla rsysloga. Komunikaty są
przetwarzane do ustrukturyzowanych danych JSON.

%package mmkubernetes
Summary:	Kubernetes message modify plugin for rsyslog
Summary(pl.UTF-8):	Wtyczka modyfikująca Kubernetes dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	liblognorm >= 2.0.3

%description mmkubernetes
rsyslog message modification module that uses metadata obtained from
the message to query Kubernetes and obtain additional metadata
relating to the container instance.

%description mmkubernetes -l pl.UTF-8
Moduł rsysloga modyfikujący komunikaty, wykorzystujący metadane
wydobyte z komunikatu do odpytania Kubernetesa i uzyskania
dodatkowych metadanych dotyczących instancji kontenera.

%package amqp
Summary:	AMQP1 output support for rsyslog
Summary(pl.UTF-8):	Obsługa wyjścia AMQP1 do rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	qpid-proton-c >= 0.9

%description amqp
This output plugin enables rsyslog to send messages to an AMQP 1.0
protocol compliant message bus.

%description amqp -l pl.UTF-8
Wtyczka wyjściowa rsysloga wysyłająca komunikaty do magistrali
zgodnej z protokołem AMQP 1.0.

%package hiredis
Summary:	REDIS output support for rsyslog
Summary(pl.UTF-8):	Obsługa wyjścia REDIS dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	hiredis >= 0.10.1

%description hiredis
REDIS output support for rsyslog.

%description hiredis -l pl.UTF-8
Obsługa wyjścia REDIS dla rsysloga.

%package dbi
Summary:	libdbi database support for rsyslog
Summary(pl.UTF-8):	Obsługa baz danych przez libdbi dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description dbi
This module supports a large number of database systems via
libdbi. Libdbi abstracts the database layer and provides drivers for
many systems. Drivers are available via the libdbi-drivers project.

%description dbi -l pl.UTF-8
Ten moduł obsłuje wiele różnych systemów baz danych poprzez libdbi.
Libdbi to abstrakcyjna warstwa baz danych, udostępniająca sterowniki
do wielu systemów; sterowniki są dostępne w projekcie libdbi-drivers.

%package mongodb
Summary:	MongoDB output support for rsyslog
Summary(pl.UTF-8):	Obsługa wyjścia MongoDB dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description mongodb
MongoDB output support for rsyslog.

%description mongodb -l pl.UTF-8
Obsługa wyjścia MongoDB dla rsysloga.

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

%package rabbitmq
Summary:	RabbitMQ output support for rsyslog
Summary(pl.UTF-8):	Obsługa wyjścia RabbitMQ dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	rabbitmq-c >= 0.2.0

%description rabbitmq
RabbitMQ output support for rsyslog.

%description rabbitmq -l pl.UTF-8
Obsługa wyjścia RabbitMQ dla rsysloga.

%package snmp
Summary:	SNMP protocol support for rsyslog
Summary(pl.UTF-8):	Obsługa protokołu SNMP dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description snmp
The rsyslog-snmp package contains the rsyslog plugin that provides the
ability to send syslog messages as SNMPv1 and SNMPv2c traps.

%description snmp -l pl.UTF-8
Ten pakiet zawiera wtyczkę rsysloga zapewniającą możliwość wysyłania
komunikatów sysloga jako pułapki SNMPv1 i SNMPv2c.

%package udpspoof
Summary:	The omudpspoof module for rsyslog
Summary(pl.UTF-8):	Moduł omudspoof dla rsysloga
Group:		Daemons
Requires:	%{name} = %{version}-%{release}

%description udpspoof
This module is similar to the regular UDP forwarder, but permits to
spoof the sender address. Also, it enables to circle through a number
of source ports.

%description udpspoof -l pl.UTF-8
Ten moduł jest podobny do zwykłego przekaźnika UDP, ale pozwana na
fałszowanie adresu nadawcy. Dodatkowo umożliwia wysyłanie
naprzemiennie z pewnej liczby portów źródłowych.

%prep
%setup -q
%patch0 -p1

%{__mv} contrib/imczmq/README{,.imczmq}
%{__mv} contrib/omczmq/README{,.omczmq}
%{__mv} plugins/omelasticsearch/README{,.omelasticsearch}

%build
%{__libtoolize}
%{__aclocal} -I m4
%{__autoconf}
%{__autoheader}
%{__automake}
%configure \
	--disable-silent-rules \
	%{?with_curl:--enable-clickhouse} \
	%{?with_curl:--enable-elasticsearch} \
	--enable-fmhash-xxhash \
	%{!?with_curl:--disable-fmhttp} \
	--enable-gnutls \
	%{?with_gssapi:--enable-gssapi-krb5} \
	--enable-imbatchreport \
	--enable-imdiag \
	%{?with_curl:--enable-imdocker} \
	--enable-imfile \
	%{?with_zeromq:--enable-imczmq} \
	%{?with_systemd:--enable-imjournal} \
	%{?with_kafka:--enable-imkafka} \
	--enable-impstats \
	--enable-imptcp \
	--enable-imtuxedoulog \
	%{?with_ksi:--enable-ksi-ls12} \
	%{?with_dbi:--enable-libdbi} \
	%{!?with_systemd:--disable-libsystemd} \
	--enable-mail \
	--enable-mmanon \
	--enable-mmaudit \
	--enable-mmcount \
	%{?with_maxminddb:--enable-mmdblookup} \
	--enable-mmfields \
	%{?with_grok:--enable-mmgrok} \
	--enable-mmjsonparse \
%if %{with curl} && %{with lognorm}
	--enable-mmkubernetes \
%endif
	%{?with_lognorm:--enable-mmnormalize} \
	--enable-mmpstrucdata \
	%{?with_openssl:--enable-mmrfc5424addhmac} \
	--enable-mmrm1stspace \
	--enable-mmsequence \
	--enable-mmsnmptrapd \
	--enable-mmtaghostname \
	--enable-mmutf8fix \
	%{?with_mysql:--enable-mysql} \
	%{?with_amqp:--enable-omamqp1} \
	%{?with_zeromq:--enable-omczmq} \
	--enable-omfile-hardened \
	%{?with_curl:--enable-omhttp} \
	%{?with_curl:--enable-omhttpfs} \
	%{?with_redis:--enable-omhiredis} \
	%{?with_systemd:--enable-omjournal} \
	%{?with_kafka:--enable-omkafka} \
	%{?with_mongodb:--enable-ommongodb} \
	--enable-omprog \
	%{?with_rabbitmq:--enable-omrabbitmq} \
	--enable-omruleset \
	--enable-omstdout \
	%{?with_tcl:--enable-omtcl} \
	--enable-omudpspoof \
	--enable-omuxsock \
	%{?with_pgsql:--enable-pgsql} \
	--enable-pmaixforwardedfrom \
	--enable-pmciscoios \
	--enable-pmcisconames \
	--enable-pmdb2diag \
	--enable-pmlastmsg \
	%{?with_lognorm:--enable-pmnormalize} \
	--enable-pmpanngfw \
	--enable-pmsnare \
	%{?with_relp:--enable-relp} \
	%{?with_rfc3195:--enable-rfc3195} \
	%{?with_snmp:--enable-snmp} \
	--enable-unlimited-select \
	--enable-usertools \
	--with-systemdsystemunitdir=%{systemdunitdir}

%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/{sysconfig,rc.d/init.d,logrotate.d,rsyslog.d} \
	$RPM_BUILD_ROOT{%{systemdunitdir},%{_sbindir},%{_mandir}/man{5,8},%{_bindir}} \
	$RPM_BUILD_ROOT/{dev,var/log}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install -p %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/rsyslog
cp -p %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/rsyslog.conf
cp -p %{SOURCE3} $RPM_BUILD_ROOT/etc/sysconfig/rsyslog
cp -p %{SOURCE4} $RPM_BUILD_ROOT/etc/logrotate.d/rsyslog
cp -p %{SOURCE5} $RPM_BUILD_ROOT%{systemdunitdir}

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
%doc AUTHORS ChangeLog README.md
%attr(755,root,root) %{_bindir}/logctl
%attr(755,root,root) %{_bindir}/rscryutil
%attr(755,root,root) %{_sbindir}/rsyslogd
%dir %{_sysconfdir}/rsyslog.d
%attr(640,root,syslog) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/rsyslog.conf
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/sysconfig/rsyslog
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/logrotate.d/rsyslog
%attr(754,root,root) /etc/rc.d/init.d/rsyslog
%attr(640,root,logs) %ghost /var/log/cron
%attr(640,root,logs) %ghost /var/log/daemon
%attr(640,root,logs) %ghost /var/log/debug
%attr(640,root,logs) %ghost /var/log/kernel
%attr(640,root,logs) %ghost /var/log/lpr
%attr(640,root,logs) %ghost /var/log/maillog
%attr(640,root,logs) %ghost /var/log/messages
%attr(640,root,logs) %ghost /var/log/secure
%attr(640,root,logs) %ghost /var/log/spooler
%attr(640,root,logs) %ghost /var/log/syslog
%attr(640,root,logs) %ghost /var/log/user
%{systemdunitdir}/rsyslog.service
%dir %{_libdir}/rsyslog
%attr(755,root,root) %{_libdir}/rsyslog/fmhash.so
%attr(755,root,root) %{_libdir}/rsyslog/imbatchreport.so
%attr(755,root,root) %{_libdir}/rsyslog/imdiag.so
%attr(755,root,root) %{_libdir}/rsyslog/imfile.so
%{?with_systemd:%attr(755,root,root) %{_libdir}/rsyslog/imjournal.so}
%attr(755,root,root) %{_libdir}/rsyslog/imklog.so
%attr(755,root,root) %{_libdir}/rsyslog/immark.so
%attr(755,root,root) %{_libdir}/rsyslog/impstats.so
%attr(755,root,root) %{_libdir}/rsyslog/imptcp.so
%attr(755,root,root) %{_libdir}/rsyslog/imtcp.so
%attr(755,root,root) %{_libdir}/rsyslog/imtuxedoulog.so
%attr(755,root,root) %{_libdir}/rsyslog/imudp.so
%attr(755,root,root) %{_libdir}/rsyslog/imuxsock.so
%attr(755,root,root) %{_libdir}/rsyslog/lmcry_gcry.so
%attr(755,root,root) %{_libdir}/rsyslog/lmnet.so
%attr(755,root,root) %{_libdir}/rsyslog/lmnetstrms.so
%attr(755,root,root) %{_libdir}/rsyslog/lmnsd_ptcp.so
%attr(755,root,root) %{_libdir}/rsyslog/lmregexp.so
%attr(755,root,root) %{_libdir}/rsyslog/lmtcpclt.so
%attr(755,root,root) %{_libdir}/rsyslog/lmtcpsrv.so
%attr(755,root,root) %{_libdir}/rsyslog/lmzlibw.so
%attr(755,root,root) %{_libdir}/rsyslog/mmanon.so
%attr(755,root,root) %{_libdir}/rsyslog/mmaudit.so
%attr(755,root,root) %{_libdir}/rsyslog/mmcount.so
%attr(755,root,root) %{_libdir}/rsyslog/mmexternal.so
%attr(755,root,root) %{_libdir}/rsyslog/mmfields.so
%attr(755,root,root) %{_libdir}/rsyslog/mmjsonparse.so
%attr(755,root,root) %{_libdir}/rsyslog/mmpstrucdata.so
%attr(755,root,root) %{_libdir}/rsyslog/mmrm1stspace.so
%attr(755,root,root) %{_libdir}/rsyslog/mmsequence.so
%attr(755,root,root) %{_libdir}/rsyslog/mmsnmptrapd.so
%attr(755,root,root) %{_libdir}/rsyslog/mmtaghostname.so
%attr(755,root,root) %{_libdir}/rsyslog/mmutf8fix.so
%attr(755,root,root) %{_libdir}/rsyslog/omfile-hardened.so
%{?with_systemd:%attr(755,root,root) %{_libdir}/rsyslog/omjournal.so}
%attr(755,root,root) %{_libdir}/rsyslog/ommail.so
%attr(755,root,root) %{_libdir}/rsyslog/omprog.so
%attr(755,root,root) %{_libdir}/rsyslog/omruleset.so
%attr(755,root,root) %{_libdir}/rsyslog/omstdout.so
%attr(755,root,root) %{_libdir}/rsyslog/omtesting.so
%attr(755,root,root) %{_libdir}/rsyslog/omuxsock.so
%attr(755,root,root) %{_libdir}/rsyslog/pmaixforwardedfrom.so
%attr(755,root,root) %{_libdir}/rsyslog/pmciscoios.so
%attr(755,root,root) %{_libdir}/rsyslog/pmcisconames.so
%attr(755,root,root) %{_libdir}/rsyslog/pmdb2diag.so
%attr(755,root,root) %{_libdir}/rsyslog/pmlastmsg.so
%attr(755,root,root) %{_libdir}/rsyslog/pmpanngfw.so
%attr(755,root,root) %{_libdir}/rsyslog/pmsnare.so
%{_mandir}/man5/rsyslog.conf.5*
%{_mandir}/man8/rsyslogd.8*

%if %{with curl}
%files http
%defattr(644,root,root,755)
%doc plugins/omelasticsearch/README.omelasticsearch
%attr(755,root,root) %{_libdir}/rsyslog/fmhttp.so
%attr(755,root,root) %{_libdir}/rsyslog/imdocker.so
%attr(755,root,root) %{_libdir}/rsyslog/omclickhouse.so
%attr(755,root,root) %{_libdir}/rsyslog/omelasticsearch.so
%attr(755,root,root) %{_libdir}/rsyslog/omhttp.so
%attr(755,root,root) %{_libdir}/rsyslog/omhttpfs.so
%endif

%if %{with gssapi}
%files gssapi
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/imgssapi.so
%attr(755,root,root) %{_libdir}/rsyslog/lmgssutil.so
%attr(755,root,root) %{_libdir}/rsyslog/omgssapi.so
%endif

%if %{with zeromq}
%files czmq
%defattr(644,root,root,755)
%doc contrib/imczmq/README.imczmq contrib/omczmq/README.omczmq
%attr(755,root,root) %{_libdir}/rsyslog/imczmq.so
%attr(755,root,root) %{_libdir}/rsyslog/omczmq.so
%endif

%if %{with kafka}
%files kafka
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/imkafka.so
%attr(755,root,root) %{_libdir}/rsyslog/omkafka.so
%endif

%if %{with relp}
%files relp
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/imrelp.so
%attr(755,root,root) %{_libdir}/rsyslog/omrelp.so
%endif

%if %{with lognorm}
%files normalize
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/mmnormalize.so
%attr(755,root,root) %{_libdir}/rsyslog/pmnormalize.so
%endif

%if %{with rfc3195}
%files rfc3195
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/im3195.so
%endif

%files gnutls
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/lmnsd_gtls.so

%if %{with ksi}
%files ksi
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/lmsig_ksi_ls12.so
%endif

%if %{with maxminddb}
%files mmdblookup
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/mmdblookup.so
%endif

%if %{with grok}
%files mmgrok
%defattr(644,root,root,755)
%doc contrib/mmgrok/README
%attr(755,root,root) %{_libdir}/rsyslog/mmgrok.so
%endif

%if %{with curl} && %{with lognorm}
%files mmkubernetes
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/mmkubernetes.so
%endif

%if %{with amqp}
%files amqp
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omamqp1.so
%endif

%if %{with redis}
%files hiredis
%defattr(644,root,root,755)
%doc contrib/omhiredis/README
%attr(755,root,root) %{_libdir}/rsyslog/omhiredis.so
%endif

%if %{with dbi}
%files dbi
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omlibdbi.so
%endif

%if %{with mongodb}
%files mongodb
%defattr(644,root,root,755)
%doc plugins/ommongodb/README
%attr(755,root,root) %{_libdir}/rsyslog/ommongodb.so
%endif

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

%if %{with rabbitmq}
%files rabbitmq
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omrabbitmq.so
%endif

%if %{with snmp}
%files snmp
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omsnmp.so
%endif

%files udpspoof
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/rsyslog/omudpspoof.so
