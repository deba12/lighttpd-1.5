#!/bin/sh

tmpdir=/tmp/lighttpd

if test x$srcdir = x; then
	srcdir=.
fi

# create test-framework
rm -rf $tmpdir
mkdir -p $tmpdir/servers/www.example.org/pages/
mkdir -p $tmpdir/servers/www.example.org/pages/dummydir/
mkdir -p $tmpdir/servers/www.example.org/pages/go/
mkdir -p $tmpdir/servers/www.example.org/pages/indexfile/
mkdir -p $tmpdir/servers/123.example.org/pages/
mkdir -p $tmpdir/logs/
mkdir -p $tmpdir/cache/
mkdir -p $tmpdir/cache/compress/

# copy everything into the right places
cp $srcdir/docroot/www/*.html \
   $srcdir/docroot/www/*.php \
   $srcdir/docroot/www/*.pl \
   $srcdir/docroot/www/*.txt $tmpdir/servers/www.example.org/pages/
cp $srcdir/docroot/www/go/*.php $tmpdir/servers/www.example.org/pages/go/
cp $srcdir/docroot/www/indexfile/*.php $tmpdir/servers/www.example.org/pages/indexfile/
cp $srcdir/docroot/123/*.txt \
   $srcdir/docroot/123/*.html \
   $srcdir/docroot/123/*.php \
   $srcdir/docroot/123/*.bla $tmpdir/servers/123.example.org/pages/
cp $srcdir/lighttpd.user $tmpdir/

printf "%-40s" "preparing infrastructure"

exit 0
