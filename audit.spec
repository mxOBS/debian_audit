Summary: User space tools for 2.6 kernel auditing
Name: audit
Version: 1.5.3
Release: 1
License: GPL
Group: System Environment/Daemons
URL: http://people.redhat.com/sgrubb/audit/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: libtool swig python-devel pkgconfig
BuildRequires: kernel-headers >= 2.6.18
BuildRequires: automake >= 1.9
BuildRequires: autoconf >= 2.59
Requires: %{name}-libs = %{version}-%{release}
Requires: chkconfig
Prereq: coreutils

%description
The audit package contains the user space utilities for
storing and searching the audit records generate by
the audit subsystem in the Linux 2.6 kernel.

%package libs
Summary: Dynamic library for libaudit
License: LGPL
Group: Development/Libraries

%description libs
The audit-libs package contains the dynamic libraries needed for 
applications to use the audit framework.

%package libs-devel
Summary: Header files and static library for libaudit
License: LGPL
Group: Development/Libraries
Requires: %{name}-libs = %{version}-%{release}
Requires: kernel-headers >= 2.6.18

%description libs-devel
The audit-libs-devel package contains the static libraries and header 
files needed for developing applications that need to use the audit 
framework libraries.

%package libs-python
Summary: Python bindings for libaudit
License: LGPL
Group: Development/Libraries
Requires: %{name}-libs = %{version}-%{release}

%description libs-python
The audit-libs-python package contains the bindings so that libaudit
and libauparse can be used by python.

%package audispd-plugins
Summary: Default plugins for the audit dispatcher
License: LGPL
Group: System Environment/Daemons

%description audispd-plugins
The audispd-plugins package contains plugins for the audit dispatcher.

%prep
%setup -q

%build
autoreconf -iv --install
%configure --sbindir=/sbin --libdir=/%{_lib}
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{sbin,etc/{sysconfig,audispd/plugins.d,rc.d/init.d}}
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man8
mkdir -p $RPM_BUILD_ROOT/%{_lib}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/audit
mkdir -p $RPM_BUILD_ROOT/%{_var}/log/audit
make DESTDIR=$RPM_BUILD_ROOT install

mkdir -p $RPM_BUILD_ROOT/%{_libdir}
# This winds up in the wrong place when libtool is involved
mv $RPM_BUILD_ROOT/%{_lib}/libaudit.a $RPM_BUILD_ROOT%{_libdir}
mv $RPM_BUILD_ROOT/%{_lib}/libauparse.a $RPM_BUILD_ROOT%{_libdir}
curdir=`pwd`
cd $RPM_BUILD_ROOT/%{_libdir}
LIBNAME=`basename \`ls $RPM_BUILD_ROOT/%{_lib}/libaudit.so.*.*.*\``
ln -s ../../%{_lib}/$LIBNAME libaudit.so
LIBNAME=`basename \`ls $RPM_BUILD_ROOT/%{_lib}/libauparse.so.*.*.*\``
ln -s ../../%{_lib}/$LIBNAME libauparse.so
cd $curdir
# Remove these items so they don't get picked up.
rm -f $RPM_BUILD_ROOT/%{_lib}/libaudit.so
rm -f $RPM_BUILD_ROOT/%{_lib}/libauparse.so
rm -f $RPM_BUILD_ROOT/%{_lib}/libaudit.la
rm -f $RPM_BUILD_ROOT/%{_lib}/libauparse.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/python?.?/site-packages/_audit.a
rm -f $RPM_BUILD_ROOT/%{_libdir}/python?.?/site-packages/_audit.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/python?.?/site-packages/_auparse.a
rm -f $RPM_BUILD_ROOT/%{_libdir}/python?.?/site-packages/_auparse.la

# On platforms with 32 & 64 bit libs, we need to coordinate the timestamp
touch -r ./audit.spec $RPM_BUILD_ROOT/etc/libaudit.conf

%clean
rm -rf $RPM_BUILD_ROOT

%post libs -p /sbin/ldconfig

%post
/sbin/chkconfig --add auditd
if [ -f /etc/auditd.conf ]; then
   mv /etc/auditd.conf /etc/audit/auditd.conf
fi
if [ -f /etc/audit.rules ]; then
   mv /etc/audit.rules /etc/audit/audit.rules
fi
if [ -f /etc/audit/auditd.conf ]; then
   tmp=`mktemp /etc/audit/auditd-post.XXXXXX`
   if [ -n $tmp ]; then
      sed 's|^#dispatcher|dispatcher|g' /etc/audit/auditd.conf > $tmp && \
      cat $tmp > /etc/audit/auditd.conf
      rm -f $tmp
   fi
fi

%preun
if [ $1 -eq 0 ]; then
   /sbin/service auditd stop > /dev/null 2>&1
   /sbin/chkconfig --del auditd
fi

%postun libs
/sbin/ldconfig 2>/dev/null

%postun
if [ $1 -ge 1 ]; then
   /sbin/service auditd condrestart > /dev/null 2>&1 || :
fi

%files libs
%defattr(-,root,root)
%attr(755,root,root) /%{_lib}/libaudit.*
%attr(755,root,root) /%{_lib}/libauparse.*
%config(noreplace) %attr(640,root,root) /etc/libaudit.conf

%files libs-devel
%defattr(-,root,root)
%{_libdir}/libaudit.a
%{_libdir}/libauparse.a
%{_libdir}/libaudit.so
%{_libdir}/libauparse.so
%{_includedir}/libaudit.h
%{_includedir}/auparse.h
%{_includedir}/auparse-defs.h
%{_mandir}/man3/*

%files libs-python
%defattr(-,root,root)
%{_libdir}/python?.?/site-packages/_audit.so
%{_libdir}/python?.?/site-packages/auparse.so
/usr/lib/python?.?/site-packages/audit.py*

%files
%defattr(-,root,root,-)
%doc  README COPYING ChangeLog sample.rules contrib/capp.rules contrib/nispom.rules contrib/lspp.rules contrib/skeleton.c init.d/auditd.cron
%attr(0644,root,root) %{_mandir}/man8/*
%attr(0644,root,root) %{_mandir}/man5/*
%attr(750,root,root) /sbin/auditctl
%attr(750,root,root) /sbin/auditd
%attr(755,root,root) /sbin/ausearch
%attr(755,root,root) /sbin/aureport
%attr(750,root,root) /sbin/autrace
%attr(750,root,root) /sbin/audispd
%attr(755,root,root) /etc/rc.d/init.d/auditd
%attr(750,root,root) %{_var}/log/audit
%attr(750,root,root) %dir /etc/audit
%attr(750,root,root) %dir /etc/audispd
%attr(750,root,root) %dir /etc/audispd/plugins.d
%attr(750,root,root) %dir %{_libdir}/audit
%config(noreplace) %attr(640,root,root) /etc/audit/auditd.conf
%config(noreplace) %attr(640,root,root) /etc/audit/audit.rules
%config(noreplace) %attr(640,root,root) /etc/sysconfig/auditd

%changelog
* Tue May 01 2007 Steve Grubb <sgrubb@redhat.com> 1.5.3-1
- Change buffer size to prevent truncation of DAEMON events with large labels
- Fix memory leaks in auparse (John Dennis)
- Update syscall tables for 2.6.21 kernel
- Update capp & lspp rules
- New python bindings for libauparse (John Dennis)

* Thu Apr 04 2007 Steve Grubb <sgrubb@redhat.com> 1.5.2-1
- New event dispatcher (James Antill)
- Apply patches fixing man pages and Makefile.am (Philipp Hahn)
- Apply patch correcting python libs permissions (Philipp Hahn)
- Fix auditd segfault on reload
- Add support for segfault anomaly message type
- Fix bug in auparse library for file pointers and descriptors
- Extract subject information out of daemon events for ausearch

* Tue Mar 20 2007 Steve Grubb <sgrubb@redhat.com> 1.5.1-1
- Updated autrace to monitor *at syscalls
- Add support in libaudit for AUDIT_BIT_TEST(^) and AUDIT_MASK_TEST (&)
- Finish reworking auditd config parser
- In auparse, interpret open, fcntl, and clone flags
- In auparse, when interpreting execve record types, run args through unencode
- Add support for OBJ_PID message type
- Event dispatcher updates

* Fri Mar 2 2007 Steve Grubb <sgrubb@redhat.com> 1.5-1
- NEW audit dispatcher program & plugin framework
- Correct hidden variables in libauparse
- Added NISPOM sample rules
- Verify accessibility of files passed in auparse_init
- Fix bug in parser library interpreting socketcalls
- Add support for stdio FILE pointer in auparse_init
- Adjust init script to allow anyone to status auditd (#230626)

* Tue Feb 20 2007 Steve Grubb <sgrubb@redhat.com> 1.4.2-1
- Add man pages
- Reduce text relocations in parser library
- Add -n option to auditd for no fork
- Add exec option to space_left, admin_space_left, disk_full,
  and disk_error - eg EXEC /usr/local/script

* Fri Feb 16 2007 Steve Grubb <sgrubb@redhat.com> 1.4.1-1
- updated audit_rule_fieldpair_data to handle perm correctly (#226780)
- Finished search options for audit parsing library
- Fix ausearch -se to work correctly
- Fix auditd init script for /usr on netdev (#228528)
- Parse avc seperms better when there are more than one

* Sun Feb 04 2007 Steve Grubb <sgrubb@redhat.com> 1.4-1
- New report about authentication attempts
- Updates for python 2.5
- update autrace to have resource usage mode
- update auditctl to support immutable config
- added audit_log_user_command function to libaudit api
- interpret capabilities
- added audit event parsing library
- updates for 2.6.20 kernel

* Sun Dec 10 2006 Steve Grubb <sgrubb@redhat.com> 1.3.1-1
- Fix a couple parsing problems (#217952)
- Add tgkill to S390* syscall tables (#218484)
- Fix error messages in ausearch/aureport
- Fix timestamp for libaudit.conf (#218053)

* Tue Nov 28 2006 Steve Grubb <sgrubb@redhat.com> 1.3-1
- ausearch & aureport implement uid/gid caching
- In ausearch & aureport, extract addr when hostname is unknown
- In ausearch & aureport, test audit log presence O_RDONLY
- New ausearch/aureport time keywords: recent, this-week, this-month, this-year
- Added --add & --delete option to aureport
- Update res parsing in config change events
- Increase the size on audit daemon buffers
- Parse avc_path records in ausearch/aureport
- ausearch has new output mode, raw, for extracting events
- ausearch/aureport can now read stdin
- Rework AVC processing in ausearch/aureport
- Added long options to ausearch and aureport

* Tue Oct 24 2006 Steve Grubb <sgrubb@redhat.com> 1.2.9-1
- In auditd if num_logs is zero, don't rotate on SIGUSR1 (#208834)
- Fix some defines in libaudit.h
- Some auditd config strings were not initialized in aureport (#211443)
- Updated man pages
- Add Netlabel event types to libaudit
- Update aureports to current audit event types
- Update autrace a little
- Deprecated all the old audit_rule functions from public API
- Drop auparse library for the moment

* Fri Sep 29 2006 Steve Grubb <sgrubb@redhat.com> 1.2.8-1
- Make internal auditd buffers bigger for context info
- Correct address resolving of hostname in logging functions
- Do not allow multiple msgtypes in same audit rule in auditctl (#207666)
- Only =, != operators for arch & inode fields in auditctl (#206427)
- Add disp_qos & dispatcher to auditd reconfigure
- Send sighup to child when no change in dispatcher during auditd reconfigure
- Cleanup file descriptor handling in auditd
- Updated audit message type table
- Remove watches from aureport since FS_WATCH is deprecated
- Add audit_log_avc back temporarily (#208152)

* Mon Sep 18 2006 Steve Grubb <sgrubb@redhat.com> 1.2.7-1
- Fix logging messages to use addr if passed.
- Apply patches from Tony Jones correcting no kernel support messages
- Updated syscall tables for 2.6.18 kernel
- Remove deprecated functions: audit_log, audit_log_avc, audit_log_if_enabled
- Disallow syscall auditing on exclude list
- Improve time handling in ausearch and aureport (#191394)
- Attempt to reconstruct full path from relative for searching

* Sat Aug 26 2006 Steve Grubb <sgrubb@redhat.com> 1.2.6-1
- Apply updates to dispatcher
- Fix a couple bugs regarding MLS labels
- Resurrect -p option
- Tighten rules with exclude filter
- Fix parsing issue which lead to segfault in some cases
- Fix option parsing to ignore malformed lines

* Thu Jul 13 2006 Steve Grubb <sgrubb@redhat.com> 1.2.5-1
- Switch out dispatcher
- Fix bug upgrading rule types

* Fri Jun 30 2006 Steve Grubb <sgrubb@redhat.com> 1.2.4-1
- Add support for the new filter key
- Update syscall tables for 2.6.17
- Add audit failure query function
- Switch out gethostbyname call with getaddrinfo
- Add audit by obj capability for 2.6.18 kernel
- Ausearch & aureport now fail if no args to -te
- New auditd.conf option to choose blocking/non-blocking dispatcher comm
- Ausearch improved search by label

* Fri May 25 2006 Steve Grubb <sgrubb@redhat.com> 1.2.3-1
- Apply patch to ensure watches only associate with exit filter
- Apply patch to correctly show new operators when new listing format is used
- Apply patch to pull kernel's audit.h into python bindings
- Collect signal sender's context

* Fri May 12 2006 Steve Grubb <sgrubb@redhat.com> 1.2.2-1
- Updates for new glibc-kernheaders
- Change auditctl to collect list of rules then delete them on -D
- Update capp.rules and lspp.rules to comment out rules for the possible list
- Add new message types
- Support sigusr1 sender identity of newer kernels
- Add support for ppid in auditctl and ausearch
- fix auditctl to trim the '/' from watches
- Move audit daemon config files to /etc/audit for better SE Linux protection

* Sun Apr 16 2006 Steve Grubb <sgrubb@redhat.com> 1.2.1-1
- New message type for trusted apps
- Add new keywords today, yesterday, now for ausearch and aureport
- Make audit_log_user_avc_message really send to syslog on error
- Updated syscall tables in auditctl
- Deprecated the 'possible' action for syscall rules in auditctl
- Update watch code to use file syscalls instead of 'all' in auditctl

* Fri Apr 7 2006 Steve Grubb <sgrubb@redhat.com> 1.2-1
- Add support for new file system auditing kernel subsystem

* Thu Apr 6 2006 Steve Grubb <sgrubb@redhat.com> 1.1.6-1
- New message types
- Support new rule format found in 2.6.17 and later kernels
- Add support for audit by role, clearance, type, sensitivity

* Wed Mar 6 2006 Steve Grubb <sgrubb@redhat.com> 1.1.5-1
- Changed audit_log_semanage_message to take new params
- In aureport, add class between syscall and permission in avc report
- Fix bug where fsync is called in debug mode
- Add optional support for tty in SYSCALL records for ausearch/aureport
- Reinstate legacy rule operator support
- Add man pages
- Auditd ignore most signals

* Wed Feb 8 2006 Steve Grubb <sgrubb@redhat.com> 1.1.4-1
- Fix bug in autrace where it didn't run on kernels without file watch support
- Add syslog message to auditd saying what program was started for dispatcher
- Remove audit_send_user from public api
- Fix bug in USER_LOGIN messages where ausearch does not translate
  msg='uid=500: into acct name (#178102).
- Change comm with dispatcher to socketpair from pipe
- Change auditd to use custom daemonize to avoid race in init scripts
- Update error message when deleting a rule that doesn't exist (#176239)
- Call shutdown_dispatcher when auditd stops
- Add new logging function audit_log_semanage_message

* Thu Jan 5 2006 Steve Grubb <sgrubb@redhat.com> 1.1.3-1
- Add timestamp to daemon_config messages (#174865)
- Add error checking of year for aureport & ausearch
- Treat af_unix sockets as files for searching and reporting
- Update capp & lspp rules to combine syscalls for higher performance
- Adjusted the chkconfig line for auditd to start a little earlier
- Added skeleton program to docs for people to write their own dispatcher with
- Apply patch from Ulrich Drepper that optimizes resource utilization
- Change ausearch and aureport to unlocked IO

* Thu Dec 5 2005 Steve Grubb <sgrubb@redhat.com> 1.1.2-1
- Add more message types

* Wed Nov 30 2005 Steve Grubb <sgrubb@redhat.com> 1.1.1-1
- Add support for alpha processors
- Update the audisp code
- Add locale code in ausearch and aureport
- Add new rule operator patch
- Add exclude filter patch
- Cleanup make files
- Add python bindings

* Wed Nov 9 2005 Steve Grubb <sgrubb@redhat.com> 1.1-1
- Add initial version of audisp. Just a placeholder at this point
- Remove -t from auditctl

* Mon Nov 7 2005 Steve Grubb <sgrubb@redhat.com> 1.0.12-1
- Add 2 more summary reports
- Add 2 more message types

