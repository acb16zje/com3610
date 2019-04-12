#!/bin/bash

c_repos=(
  "https://github.com/apache/xerces-c.git"
  "https://github.com/madler/zlib.git"
  "https://github.com/openssl/openssl.git"
  "https://github.com/unicode-org/icu.git"
  "https://github.com/ImageMagick/ImageMagick.git"
  "https://github.com/GNOME/libxml2.git"
  "https://github.com/curl/curl.git"
  "https://github.com/apache/httpd.git"
  "https://github.com/libarchive/libarchive.git"
  "https://github.com/glennrp/libpng.git"
  "https://github.com/v8/v8.git"
  "https://github.com/GNOME/libxslt.git"
  "https://github.com/apache/xalan-c.git"
  "https://github.com/libtom/libtomcrypt.git"
)

java_repos=(
  "https://github.com/apache/httpcomponents-client.git"
  "https://github.com/apache/cxf.git"
  "https://github.com/spring-projects/spring-framework.git"
  "https://github.com/apache/poi.git"
  "https://github.com/apache/commons-fileupload.git"
  "https://github.com/apache/tomcat.git"
  "https://github.com/apache/axis2-java.git"
  "https://github.com/apache/xalan-j.git"
  "https://github.com/bcgit/bc-java.git"
  "https://github.com/apache/struts.git"
  "https://github.com/eclipse/jetty.project.git"
  "https://github.com/apache/flex-sdk.git"
  "https://github.com/apache/batik.git"
  "https://github.com/spring-projects/spring-security.git"
  "https://github.com/apache/activemq.git"
  "https://github.com/apache/wss4j.git"
  "https://github.com/apache/geronimo.git"
  "https://github.com/apache/camel.git"
  "https://github.com/apache/cordova-android.git"
  "https://github.com/apache/cocoon.git"
)

python_repos=(
  "https://github.com/ansible/ansible.git"
  "https://github.com/pyca/bcrypt.git"
  "https://github.com/python/cpython.git"
  "https://github.com/django/django.git"
  "https://github.com/home-assistant/home-assistant.git"
  "https://github.com/pyca/pyopenssl.git"
  "https://github.com/kennethreitz/requests.git"
  "https://github.com/urllib3/urllib3.git"
  "https://github.com/wbond/asn1crypto.git"
  "https://github.com/boto/botocore.git"
  "https://github.com/pyca/cryptography.git"
  "https://github.com/pallets/flask.git"
  "https://github.com/vmware/photon.git"
  "https://github.com/certifi/python-certifi.git"
  "https://github.com/sqlmapproject/sqlmap.git"
)

DIR=`pwd`

mkdir -p ../repositories
mkdir -p ../repositories/c
mkdir -p ../repositories/java
mkdir -p ../repositories/python

for c_repo in "${c_repos[@]}"; do
  cd "$DIR/../repositories/c" && git clone --single-branch --bare $c_repo
done

for java_repo in "${java_repos[@]}"; do
  cd "$DIR/../repositories/java" && git clone --single-branch --bare $java_repo
done

for python_repo in "${python_repos[@]}"; do
  cd "$DIR/../repositories/python" && git clone --single-branch --bare $python_repo
done
