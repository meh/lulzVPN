have_pthreads=no
have_readline=no
have_ssl=no

AC_PREREQ([2.63])
AC_INIT([lulznet], [0.1.1])
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([src/include/lulznet/_config.h])
AC_PROG_CC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h termio.h unistd.h])

AC_SEARCH_LIBS([pthread_create], [pthread],[have_pthreads=yes])

if test "x${have_pthreads}" = xno; then
	echo "------------------------------------------"
	echo " The pthread library is required to build "
	echo " lulznet. Stopping..."
	echo "------------------------------------------"
	(exit 1); exit 1;
fi

AC_CHECK_HEADERS([pthread.h], [],[have_pthreads=no])

if test "x${have_pthreads}" = xno; then
	echo "------------------------------------------"
	echo " The pthread header file is required to"
	echo " build lulznet. Stopping..."
	echo "------------------------------------------"
	(exit 1); exit 1;
fi

AC_SEARCH_LIBS([readline], [readline],[have_readline=yes])

if test "x${have_readline}" = xno; then
	echo "------------------------------------------"
	echo " The readline library is required to"
	echo " build lulznet. Stopping..."
	echo "------------------------------------------"
	(exit 1); exit 1;
fi

AC_CHECK_HEADERS([readline/readline.h readline/history.h], [],[have_readline=no])

if test "x${have_readline}" = xno; then
	echo "------------------------------------------"
	echo " The readline header files is required to"
	echo " build lulznet. Stopping..."
	echo "------------------------------------------"
	(exit 1); exit 1;
fi

AC_SEARCH_LIBS([SSL_CTX_new], [ssl],[have_ssl=yes])

if test "x${have_ssl}" = xno; then
	echo "------------------------------------------"
	echo " The ssl library is required to"
	echo " build lulznet. Stopping..."
	echo "------------------------------------------"
	(exit 1); exit 1;
fi

AC_CHECK_HEADERS([openssl/ssl.h openssl/err.h openssl/evp.h openssl/sha.h openssl/md5.h], [],[have_ssl=no])

if test "x${have_ssl}" = xno; then
	echo "------------------------------------------"
	echo " The ssl header files is required to"
	echo " build lulznet. Stopping..."
	echo "------------------------------------------"
	(exit 1); exit 1;
fi

#TODO: parse kernel config

AC_C_INLINE
AC_TYPE_SIZE_T
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gethostbyname memset select socket strerror])
AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

echo "Cross fingers and type make"
