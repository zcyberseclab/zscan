from collections import defaultdict
import re
import yaml
import os
import shutil
from pathlib import Path
import requests
from datetime import datetime, timedelta
from io import BytesIO
import zipfile

class NucleiTemplateClassifier:
    def __init__(self):
        # 获取当前脚本所在目录的上一级目录
        root_dir = os.path.dirname(os.path.dirname(__file__))
        
        # 基础配置
        self.nuclei_templates = "nuclei-templates"  
        self.classified_templates = os.path.join(root_dir, "pocs")
        self.download_url = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/master.zip"
        self.update_interval = 7  
        
 
        self.component_patterns = {
            # 3
            "3cx": r"3cx[_-]|3cx\b|/3cx/",
 
            "74cms": r"74cms[_-]|74cms\b|/74cms/",
            
            # A
            "alert-manager": r"Alert Manager",
            "anchor-cms": r"Anchor CMS",
            "acexy": r"acexy[_-]|acexy\b|/acexy/",
            "artica": r"artica[_-]|artica\b|/artica/",
            "alibaba-metadata-service": r"Metadata Service",
            "appserv": r"appserv[_-]|appserv\b|/appserv/",
            "apereo-cas": r"apereo[_-]|apereo\b|/apereo/",
            "auerswald": r"auerswald[_-]|auerswald\b|/auerswald/",
            "aveva": r"aveva[_-]|aveva\b|/aveva/",
            "auerswald": r"auerswald[_-]|auerswald\b|/auerswald/",
            "aryanic-highMail": r"highMail[_-]|highMail\b|/highMail/",
            "aem": r"aem[_-]|aem\b|/aem/",
            "accent": r"accent[_-]|accent\b|/accent/",
            "ace": r"ace[_-]|ace\b|/ace/",
            "adb": r"adb[_-]|adb\b|/adb/",
            "airflow": r"airflow[_-]|airflow\b|/airflow/",
            "alphaweb": r"alphaweb[_-]|alphaweb\b|/alphaweb/",
            "alumni": r"alumni[_-]|alumni\b|/alumni/",
            "amazon": r"amazon[_-]|amazon\b|/amazon/",
            "ampache": r"ampache[_-]|ampache\b|/ampache/",
            "android": r"android[_-]|android\b|/android/",
            "ansible": r"ansible[_-]|ansible\b|/ansible/",
            "apcu": r"apcu[_-]|apcu\b|/apcu/",
            "apollo": r"apollo[_-]|apollo\b|/apollo/",
            "appspec": r"appspec[_-]|appspec\b|/appspec/",
            "appveyor": r"appveyor[_-]|appveyor\b|/appveyor/",
            "arl": r"arl[_-]|arl\b|/arl/",
            "artifactory": r"artifactory[_-]|artifactory\b|/artifactory/",
            "asanhamayesh": r"asanhamayesh[_-]|asanhamayesh\b|/asanhamayesh/",
            "atlassian": r"atlassian[_-]|atlassian\b|/atlassian/",
            "atom": r"atom[_-]|atom\b|/atom/",
            "audiocodes": r"audiocodes[_-]|audiocodes\b|/audiocodes/",
            "avtech": r"avtech[_-]|avtech\b|/avtech/",
            "awstats": r"awstats[_-]|awstats\b|/awstats/",
            "azkaban": r"azkaban[_-]|azkaban\b|/azkaban/",
            "activehelper": r"activehelper[_-]|activehelper\b|/activehelper/",
    
            "alt-n": r"alt[_-]n[_-]|mdaemon[_-]|alt[_-]n\b|mdaemon\b|/alt[_-]n/|/mdaemon/",

            "apache": r"apache[_-]|apache\b|/apache/",
            "apache-airflow": r"airflow[_-]|airflow\b|/airflow/",
            "apache-activemq": r"activemq[_-]|activemq\b|/activemq/",
            "apache-apisix": r"apisix[_-]|apisix\b|/apisix/",
            "apache-cassandra": r"cassandra[_-]|cassandra\b|/cassandra/",
            "apache-couchdb": r"couchdb[_-]|couchdb\b|/couchdb/",
            "apache-druid": r"druid[_-]|druid\b|/druid/",
            "apache-dubbo": r"dubbo[_-]|dubbo\b|/dubbo/",
            "apache-flink": r"flink[_-]|flink\b|/flink/",
            "apache-hadoop": r"hadoop[_-]|hadoop\b|/hadoop/",
            "apache-hbase": r"hbase[_-]|hbase\b|/hbase/",
            "apache-hive": r"hive[_-]|hive\b|/hive/",
            "apache-httpd": r"httpd[_-]|httpd\b|/httpd/",
            "apache-kafka": r"kafka[_-]|kafka\b|/kafka/",
            "apache-karaf": r"karaf[_-]|karaf\b|/karaf/",
            "apache-nifi": r"nifi[_-]|nifi\b|/nifi/",
            "apache-ofbiz": r"ofbiz[_-]|ofbiz\b|/ofbiz/",
            "apache-solr": r"solr[_-]|solr\b|/solr/",
            "apache-spark": r"spark[_-]|spark\b|/spark/",
            "apache-storm": r"storm[_-]|storm\b|/storm/",
            "apache-struts": r"struts[_-]|struts\b|/struts/|struts2[_-]|struts2\b|/struts2/",
            "apache-tomcat": r"tomcat[_-]|tomcat\b|/tomcat/",
            "apache-zookeeper": r"zookeeper[_-]|zookeeper\b|/zookeeper/",
            "apache-skywalking": r"skywalking[_-]|skywalking\b|/skywalking/",
            "apache-shiro": r"shiro[_-]|shiro\b|/shiro/",
            "apache-superset": r"superset[_-]|superset\b|/superset/",
            "apache-pulsar": r"pulsar[_-]|pulsar\b|/pulsar/",
            "apache-rocketmq": r"rocketmq[_-]|rocketmq\b|/rocketmq/",
            "apache-maven": r"maven[_-]|maven\b|/maven/",
            "apache-mesos": r"mesos[_-]|mesos\b|/mesos/",
            "apache-log4j": r"log4j[_-]|log4j\b|/log4j/",
 
    
             
            "aws-s3": r"aws[_-]s3[_-]|s3[_-]bucket[_-]|aws[_-]s3\b|s3[_-]bucket\b|/aws[_-]s3/|/s3/",
            "aws-ec2": r"aws[_-]ec2[_-]|ec2[_-]|aws[_-]ec2\b|ec2\b|/aws[_-]ec2/|/ec2/",
            "aws-lambda": r"aws[_-]lambda[_-]|lambda[_-]|aws[_-]lambda\b|lambda\b|/aws[_-]lambda/",
            "aws-iam": r"aws[_-]iam[_-]|iam[_-]|aws[_-]iam\b|iam\b|/aws[_-]iam/",
            "aws-cloudfront": r"cloudfront[_-]|cloudfront\b|/cloudfront/",
            "aws-rds": r"aws[_-]rds[_-]|rds[_-]|aws[_-]rds\b|rds\b|/aws[_-]rds/",
            # B
            "bamboo": r"bamboo[_-]|bamboo\b|/bamboo/",
            "belkin-router": r"belkin[_-]|belkin\b|/belkin/",
            "b2evolution": r"b2evolution[_-]|b2evolution\b|/b2evolution/",
            "bitrix": r"bitrix[_-]|bitrix\b|/bitrix/",
            "brasileiro": r"brasileiro[_-]|brasileiro\b|/brasileiro/",
            "badarg": r"badarg[_-]|badarg\b|/badarg/",
            "bagisto": r"bagisto[_-]|bagisto\b|/bagisto/",
            "basic": r"basic[_-]|basic\b|/basic/",
            "behat": r"behat[_-]|behat\b|/behat/",
            "beward": r"beward[_-]|beward\b|/beward/",
            "binom": r"binom[_-]|binom\b|/binom/",
 
            "blesta": r"blesta[_-]|blesta\b|/blesta/",
            "blue": r"blue[_-]|blue\b|/blue/",
            "brother": r"brother[_-]|brother\b|/brother/",
            "bullwark": r"bullwark[_-]|bullwark\b|/bullwark/",
            "beyondtrust": r"beyondtrust[_-]|beyondtrust\b|/beyondtrust/",
            "barco": r"barco[_-]|barco\b|/barco/",
            "boa": r"boa[_-]|boa\b|/boa/",

            # C
            "clickdesk": r"clickdesk[_-]|clickdesk\b|/clickdesk/",
            "chiyu": r"chiyu[_-]|chiyu\b|/chiyu/",
            "citrix": r"citrix[_-]|citrix\b|/citrix/",
            "comodo": r"comodo[_-]|comodo\b|/comodo/",
            "cyberoam": r"cyberoam[_-]|cyberoam\b|/cyberoam/",

            "confluence": r"confluence[_-]|confluence\b|/confluence/",
            "cmsimple": r"cmsimple[_-]|cmsimple\b|/cmsimple/",
            "coldfusion": r"coldfusion[_-]|coldfusion\b|/coldfusion/",
            "canvas": r"canvas[_-]|canvas\b|/canvas/",
            "cobranca": r"cobranca[_-]|cobranca\b|/cobranca/",
            "cofax": r"cofax[_-]|cofax\b|/cofax/",
            "cache": r"cache[_-]|cache\b|/cache/",
            "caddy": r"caddy[_-]|caddy\b|/caddy/",
            "cadvisor": r"cadvisor[_-]|cadvisor\b|/cadvisor/",
            "cakephp": r"cakephp[_-]|cakephp\b|/cakephp/",
            "cgi": r"cgi[_-]|cgi\b|/cgi/",
            "circarlife": r"circarlife[_-]|circarlife\b|/circarlife/",
            "circleci": r"circleci[_-]|circleci\b|/circleci/",
            "ckan": r"ckan[_-]|ckan\b|/ckan/",
            "clamav": r"clamav[_-]|clamav\b|/clamav/",
            "clickhouse": r"clickhouse[_-]|clickhouse\b|/clickhouse/",
            "clockwatch": r"clockwatch[_-]|clockwatch\b|/clockwatch/",
            "clockwork": r"clockwork[_-]|clockwork\b|/clockwork/",
           
            "cloudcenter": r"cloudcenter[_-]|cloudcenter\b|/cloudcenter/",
            "cloudinary": r"cloudinary[_-]|cloudinary\b|/cloudinary/",
            "cobbler": r"cobbler[_-]|cobbler\b|/cobbler/",
            "codeception": r"codeception[_-]|codeception\b|/codeception/",
            "codeigniter": r"codeigniter[_-]|codeigniter\b|/codeigniter/",
            "codemeter": r"codemeter[_-]|codemeter\b|/codemeter/",
            "codis": r"codis[_-]|codis\b|/codis/",
            "collectd": r"collectd[_-]|collectd\b|/collectd/",
            "command": r"command[_-]|command\b|/command/",
            "comtrend": r"comtrend[_-]|comtrend\b|/comtrend/",
            "concrete": r"concrete[_-]|concrete\b|/concrete/",
            "concrete5": r"concrete5[_-]|concrete5\b|/concrete5/",
            "contacam": r"contacam[_-]|contacam\b|/contacam/",
            "contentify": r"contentify[_-]|contentify\b|/contentify/",
            "core": r"core[_-]|core\b|/core/",
            "coremail": r"coremail[_-]|coremail\b|/coremail/",
            "couchdb": r"couchdb[_-]|couchdb\b|/couchdb/",
            "credentials": r"credentials[_-]|credentials\b|/credentials/",
            "crystal": r"crystal[_-]|crystal\b|/crystal/",
            "cisco": r"cisco[_-]|cisco\b|/cisco/",
            "cisco-asa": r"cisco[_-]asa[_-]|asa[_-]|cisco[_-]asa\b|asa\b|/cisco[_-]asa/|/asa/",
            "cisco-ios": r"cisco[_-]ios[_-]|ios[_-]|cisco[_-]ios\b|ios\b|/cisco[_-]ios/|/ios/",
            "cisco-webex": r"cisco[_-]webex[_-]|webex[_-]|cisco[_-]webex\b|webex\b|/cisco[_-]webex/|/webex/",
            "cisco-firepower": r"cisco[_-]firepower[_-]|firepower[_-]|cisco[_-]firepower\b|firepower\b|/cisco[_-]firepower/|/firepower/",
            "cisco-ucs": r"cisco[_-]ucs[_-]|ucs[_-]|cisco[_-]ucs\b|ucs\b|/cisco[_-]ucs/|/ucs/",
            "cisco-wlc": r"cisco[_-]wlc[_-]|wlc[_-]|cisco[_-]wlc\b|wlc\b|/cisco[_-]wlc/|/wlc/",
            "cisco-prime": r"cisco[_-]prime[_-]|prime[_-]|cisco[_-]prime\b|prime\b|/cisco[_-]prime/|/prime/",
            "cisco-meraki": r"cisco[_-]meraki[_-]|meraki[_-]|cisco[_-]meraki\b|meraki\b|/cisco[_-]meraki/|/meraki/",
            "cisco-anyconnect": r"cisco[_-]anyconnect[_-]|anyconnect[_-]|cisco[_-]anyconnect\b|anyconnect\b|/cisco[_-]anyconnect/|/anyconnect/",
            "cisco-jabber": r"cisco[_-]jabber[_-]|jabber[_-]|cisco[_-]jabber\b|jabber\b|/cisco[_-]jabber/|/jabber/",
            "cisco-nexus": r"cisco[_-]nexus[_-]|nexus[_-]|cisco[_-]nexus\b|nexus\b|/cisco[_-]nexus/|/nexus/",
            "cisco-hyperflex": r"cisco[_-]hyperflex[_-]|hyperflex[_-]|cisco[_-]hyperflex\b|hyperflex\b|/cisco[_-]hyperflex/|/hyperflex/",
            "cisco-intersight": r"cisco[_-]intersight[_-]|intersight[_-]|cisco[_-]intersight\b|intersight\b|/cisco[_-]intersight/|/intersight/",
                        
            "citrix": r"citrix[_-]|citrix\b|/citrix/",
            "citrix-adc": r"citrix[_-]adc[_-]|netscaler[_-]|citrix[_-]adc\b|netscaler\b|/citrix[_-]adc/|/netscaler/",
            "citrix-gateway": r"citrix[_-]gateway[_-]|gateway[_-]|citrix[_-]gateway\b|/citrix[_-]gateway/",
            "citrix-hypervisor": r"citrix[_-]hypervisor[_-]|xenserver[_-]|citrix[_-]hypervisor\b|xenserver\b|/citrix[_-]hypervisor/|/xenserver/",
            "citrix-virtual-apps": r"citrix[_-]virtual[_-]apps[_-]|xenapp[_-]|citrix[_-]virtual[_-]apps\b|xenapp\b|/citrix[_-]virtual[_-]apps/|/xenapp/",
            "citrix-virtual-desktops": r"citrix[_-]virtual[_-]desktops[_-]|xendesktop[_-]|citrix[_-]virtual[_-]desktops\b|xendesktop\b|/citrix[_-]virtual[_-]desktops/|/xendesktop/",
            "citrix-endpoint-management": r"citrix[_-]endpoint[_-]|xenmobile[_-]|citrix[_-]endpoint\b|xenmobile\b|/citrix[_-]endpoint/|/xenmobile/",
            "citrix-workspace": r"citrix[_-]workspace[_-]|workspace[_-]|citrix[_-]workspace\b|workspace\b|/citrix[_-]workspace/",
            "citrix-sd-wan": r"citrix[_-]sd[_-]wan[_-]|sd[_-]wan[_-]|citrix[_-]sd[_-]wan\b|/citrix[_-]sd[_-]wan/",
            "citrix-application-delivery-management": r"citrix[_-]adm[_-]|netscaler[_-]mas[_-]|citrix[_-]adm\b|netscaler[_-]mas\b|/citrix[_-]adm/|/netscaler[_-]mas/",
            "citrix-analytics": r"citrix[_-]analytics[_-]|analytics[_-]|citrix[_-]analytics\b|/citrix[_-]analytics/",
            "citrix-content-collaboration": r"citrix[_-]content[_-]|sharefile[_-]|citrix[_-]content\b|sharefile\b|/citrix[_-]content/|/sharefile/",
            "citrix-cloud": r"citrix[_-]cloud[_-]|citrix[_-]cloud\b|/citrix[_-]cloud/",
            "cassandra": r"cassandra[_-]|cassandra\b|/cassandra/",
             

            # D
            "drupal": r"drupal[_-]|drupal\b|/drupal/",
            "d-link": r"D-Link[_-]|D-Link\b|/D-Link/",
            "database": r"database[_-]|database\b|/database/",
            "datahub": r"datahub[_-]|datahub\b|/datahub/",
            "dataiku": r"dataiku[_-]|dataiku\b|/dataiku/",
            "dbeaver": r"dbeaver[_-]|dbeaver\b|/dbeaver/",
            "dell": r"dell[_-]|dell\b|/dell/",
            "deos": r"deos[_-]|deos\b|/deos/",
            "dgraph": r"dgraph[_-]|dgraph\b|/dgraph/",
            "dicoogle": r"dicoogle[_-]|dicoogle\b|/dicoogle/",
            "discourse": r"discourse[_-]|discourse\b|/discourse/",
            "docker": r"docker[_-]|docker\b|/docker/",
            "dockerfile": r"dockerfile[_-]|dockerfile\b|/dockerfile/",
            "docmosis": r"docmosis[_-]|docmosis\b|/docmosis/",
            "dokuwiki": r"dokuwiki[_-]|dokuwiki\b|/dokuwiki/",
            "dolibarr": r"dolibarr[_-]|dolibarr\b|/dolibarr/",
            "dom": r"dom[_-]|dom\b|/dom/",
            "dropbear": r"dropbear[_-]|dropbear\b|/dropbear/",
   
            "dss": r"dss[_-]|dss\b|/dss/",
            "dvwa": r"dvwa[_-]|dvwa\b|/dvwa/",
            "dynatrace": r"dynatrace[_-]|dynatrace\b|/dynatrace/",
            "dzzoffice": r"dzzoffice[_-]|dzzoffice\b|/dzzoffice/",
            "django": r"django[_-]|django\b|/django/",
            "drill":  r"drill[_-]|drill\b|/drill/",

            # E
            "easyscripts": r"easyscripts[_-]|easyscripts\b|/easyscripts/",
            "ec2": r"ec2[_-]|ec2\b|/ec2/",
            "ecology": r"ecology[_-]|ecology\b|/ecology/",
            "ecshop": r"ecshop[_-]|ecshop\b|/ecshop/",
            "editor": r"editor[_-]|editor\b|/editor/",
            "eibiz": r"eibiz[_-]|eibiz\b|/eibiz/",
            "elfinder": r"elfinder[_-]|elfinder\b|/elfinder/",
            "elmah": r"elmah[_-]|elmah\b|/elmah/",
            "emqx": r"emqx[_-]|emqx\b|/emqx/",
            "environment": r"environment[_-]|environment\b|/environment/",
            "envoy": r"envoy[_-]|envoy\b|/envoy/",
            "error": r"error[_-]|error\b|/error/",
            "eshop": r"eshop[_-]|eshop\b|/eshop/",
            "espeasy": r"espeasy[_-]|espeasy\b|/espeasy/",
            "elasticsearch": r"elasticsearch[_-]|elasticsearch\b|/elasticsearch/",
            "ewebs": r"ewebs[_-]|ewebs\b|/ewebs/",
            "exacqvision": r"exacqvision[_-]|exacqvision\b|/exacqvision/",
 
    
            "express": r"express[_-]|express\b|/express/",
            "eyelock": r"eyelock[_-]|eyelock\b|/eyelock/",
            "etherpad": r"etherpad[_-]|etherpad\b|/etherpad/",

            # F
    
            "facebook": r"facebook[_-]|facebook\b|/facebook/",
            "facturascripts": r"facturascripts[_-]|facturascripts\b|/facturascripts/",
            "fastjson": r"fastjson[_-]|fastjson\b|/fastjson/",
            "fatpipe": r"fatpipe[_-]|fatpipe\b|/fatpipe/",
            "fcm": r"fcm[_-]|fcm\b|/fcm/",
            "filezilla": r"filezilla[_-]|filezilla\b|/filezilla/",
            "finereport": r"finereport[_-]|finereport\b|/finereport/",
            "firebase": r"firebase[_-]|firebase\b|/firebase/",
            "flatpress": r"flatpress[_-]|flatpress\b|/flatpress/",
            "flexbe": r"flexbe[_-]|flexbe\b|/flexbe/",
            "flir": r"flir[_-]|flir\b|/flir/",
            "flywheel": r"flywheel[_-]|flywheel\b|/flywheel/",
            "frp": r"frp[_-]|frp\b|/frp/",
            "ftp": r"ftp[_-]|ftp\b|/ftp/",
            "ffay": r"ffay[_-]|ffay\b|/ffay/",
            "flask": r"flask[_-]|flask\b|/flask/",
            "frontpage": r"frontpage[_-]|frontpage\b|/frontpage/",
            "fortinet": r"fortinet[_-]|fortinet\b|/fortinet/",
            
            "f5": r"f5[_-]|f5\b|/f5/",
 
            "fastvue": r"fastvue[_-]|fastvue\b|/fastvue/",
            # G
            "ganglia": r"ganglia[_-]|ganglia\b|/ganglia/",
            "glances": r"glances[_-]|glances\b|/glances/",
            "geniusocean": r"geniusocean[_-]|geniusocean\b|/geniusocean/",
            "geoserver": r"geoserver[_-]|geoserver\b|/geoserver/",
            "getsimple": r"getsimple[_-]|getsimple\b|/getsimple/",
            "git": r"git[_-]|git\b|/git/",
            "gitea": r"gitea[_-]|gitea\b|/gitea/",
            "github": r"github[_-]|github\b|/github/",
            "gitlist": r"gitlist[_-]|gitlist\b|/gitlist/",
            "golang": r"golang[_-]|golang\b|/golang/",
            "glpi": r"glpi[_-]|glpi\b|/glpi/",
            "gnuboard": r"gnuboard[_-]|gnuboard\b|/gnuboard/",
            "gocd": r"gocd[_-]|gocd\b|/gocd/",
            "gogs": r"gogs[_-]|gogs\b|/gogs/",
            "google": r"google[_-]|google\b|/google/",
            "gophish": r"gophish[_-]|gophish\b|/gophish/",
            "grafana": r"grafana[_-]|grafana\b|/grafana/",
            "graphql": r"graphql[_-]|graphql\b|/graphql/",
            "groupoffice": r"groupoffice[_-]|groupoffice\b|/groupoffice/",
            "gsoap": r"gsoap[_-]|gsoap\b|/gsoap/",
            "guacamole": r"guacamole[_-]|guacamole\b|/guacamole/",
            "gitlab": r"gitlab[_-]|gitlab\b|/gitlab/",
            "gcp": r"gcp[_-]|gcp\b|/gcp/",
            "grafana": r"grafana[_-]|grafana\b|/grafana/",
            "glowroot": r"glowroot[_-]|glowroot\b|/glowroot/",

            # H
            "horde": r"horde[_-]|horde\b|/horde/",
            "h3c": r"h3c[_-]|h3c\b|/h3c/",
            "hanming": r"hanming[_-]|hanming\b|/hanming/",
            "hashicorp": r"hashicorp[_-]|hashicorp\b|/hashicorp/",
            "hasura": r"hasura[_-]|hasura\b|/hasura/",
            "header": r"header[_-]|header\b|/header/",
            "healthchecks": r"healthchecks[_-]|healthchecks\b|/healthchecks/",
            "hfs": r"hfs[_-]|hfs\b|/hfs/",
            "hiboss": r"hiboss[_-]|hiboss\b|/hiboss/",
            "hikvision": r"hikvision[_-]|hikvision\b|/hikvision/",
            "hivequeue": r"hivequeue[_-]|hivequeue\b|/hivequeue/",
            "hjtcloud": r"hjtcloud[_-]|hjtcloud\b|/hjtcloud/",
            "homeautomation": r"homeautomation[_-]|homeautomation\b|/homeautomation/",
          
            "hongdian": r"hongdian[_-]|hongdian\b|/hongdian/",
            "hospital": r"hospital[_-]|hospital\b|/hospital/",
            "hp": r"hp[_-]|hp\b|/hp/",
            "hpe": r"hpe[_-]|hpe\b|/hpe/",
            "hrsale": r"hrsale[_-]|hrsale\b|/hrsale/",
            "httpbin": r"httpbin[_-]|httpbin\b|/httpbin/",
            "huijietong": r"huijietong[_-]|huijietong\b|/huijietong/",
            "hybris": r"hybris[_-]|hybris\b|/hybris/",
            "ha-proxy": r"HA Proxy",

            # I
            "imperva": r"imperva[_-]|imperva\b|/imperva/",
            "iis": r"iis[_-]|iis\b|/iis/",
            "ibm": r"ibm[_-]|ibm\b|/ibm/",
            "iceflow": r"iceflow[_-]|iceflow\b|/iceflow/",
            "icewarp": r"icewarp[_-]|icewarp\b|/icewarp/",
            "idemia": r"idemia[_-]|idemia\b|/idemia/",
            "improper": r"improper[_-]|improper\b|/improper/",
            "insecure": r"insecure[_-]|insecure\b|/insecure/",
            "inspur": r"inspur[_-]|inspur\b|/inspur/",
            "interlib": r"interlib[_-]|interlib\b|/interlib/",
 
            "ioncube": r"ioncube[_-]|ioncube\b|/ioncube/",
        
            "iotawatt": r"iotawatt[_-]|iotawatt\b|/iotawatt/",
            "iptime": r"iptime[_-]|iptime\b|/iptime/",

            # J
            "jira": r"jira[_-]|jira\b|/jira/",
            "jenkins": r"jenkins[_-]|jenkins\b|/jenkins/",
            "jaeger": r"jaeger[_-]|jaeger\b|/jaeger/",
            "jamf": r"jamf[_-]|jamf\b|/jamf/",
            "javamelody": r"javamelody[_-]|javamelody\b|/javamelody/",
            "jdbc": r"jdbc[_-]|jdbc\b|/jdbc/",
            "jeewms": r"jeewms[_-]|jeewms\b|/jeewms/",
            "jetty": r"jetty[_-]|jetty\b|/jetty/",
            "jexboss": r"jexboss[_-]|jexboss\b|/jexboss/",
            "jfrog": r"jfrog[_-]|jfrog\b|/jfrog/",
            "jinfornet": r"jinfornet[_-]|jinfornet\b|/jinfornet/",
            "jolokia": r"jolokia[_-]|jolokia\b|/jolokia/",
            "jsapi": r"jsapi[_-]|jsapi\b|/jsapi/",
            "jupyter": r"jupyter[_-]|jupyter\b|/jupyter/",
            "jupyterhub": r"jupyterhub[_-]|jupyterhub\b|/jupyterhub/",
            "jboss": r"jboss[_-]|jboss\b|/jboss/",
            "joomla": r"joomla[_-]|joomla\b|/joomla/",

            # K
            "kafdrop": r"kafdrop[_-]|kafdrop\b|/kafdrop/",
   
            "kanboard": r"kanboard[_-]|kanboard\b|/kanboard/",
            "karel": r"karel[_-]|karel\b|/karel/",
            "karma": r"karma[_-]|karma\b|/karma/",
            "kavita": r"kavita[_-]|kavita\b|/kavita/",
            "kettle": r"kettle[_-]|kettle\b|/kettle/",
            "kingdee": r"kingdee[_-]|kingdee\b|/kingdee/",
            "kubeflow": r"kubeflow[_-]|kubeflow\b|/kubeflow/",
            "kyan": r"kyan[_-]|kyan\b|/kyan/",
            "kyocera": r"kyocera[_-]|kyocera\b|/kyocera/",
            "kubernetes": r"kubernetes[_-]|kubernetes\b|/kubernetes/",
            "kibana": r"kibana[_-]|kibana\b|/kibana/",
            "kubecost":r"kubecost[_-]|kubecost\b|/kubecost/",
            # L
            "l-soft":r"L-Soft[_-]|L-Soft\b|/L-Soft/",
            "lotus": r"lotus[_-]|lotus\b|/lotus/",
            "ldap": r"ldap[_-]|ldap\b|/ldap/",
            "libvirt": r"libvirt[_-]|libvirt\b|/libvirt/",
            "limesurvey": r"limesurvey[_-]|limesurvey\b|/limesurvey/",
            "linkedin": r"linkedin[_-]|linkedin\b|/linkedin/",
            "linktap": r"linktap[_-]|linktap\b|/linktap/",
            "linux": r"linux[_-]|linux\b|/linux/",
            "lmszai": r"lmszai[_-]|lmszai\b|/lmszai/",
            "locust": r"locust[_-]|locust\b|/locust/",
            "loqate": r"loqate[_-]|loqate\b|/loqate/",
            "lucee": r"lucee[_-]|lucee\b|/lucee/",
            "luftguitar": r"luftguitar[_-]|luftguitar\b|/luftguitar/",
            "lutron": r"lutron[_-]|lutron\b|/lutron/",
            "lvm": r"lvm[_-]|lvm\b|/lvm/",
            "lvmeng": r"lvmeng[_-]|lvmeng\b|/lvmeng/",
            "lychee": r"lychee[_-]|lychee\b|/lychee/",
            "logstash": r"logstash[_-]|logstash\b|/logstash/",
            "laravel": r"laravel[_-]|laravel\b|/laravel/",
         

            "lansweeper": r"lansweeper[_-]|lansweeper\b|/lansweeper/",
          
            # M
            "monitorr": r"monitorr[_-]|monitorr\b|/monitorr/",
            "mercury-router": r"mercury[_-]|mercury\b|/mercury/",
            "mirasys": r"mirasys[_-]|mirasys\b|/mirasys/",
            "motorola": r"motorola[_-]|motorola\b|/motorola/",
            "maccmsv10": r"maccmsv10[_-]|maccmsv10\b|/maccmsv10/",
            "magento": r"magento[_-]|magento\b|/magento/",
            "magicflow": r"magicflow[_-]|magicflow\b|/magicflow/",
            "mailchimp": r"mailchimp[_-]|mailchimp\b|/mailchimp/",
            "mailgun": r"mailgun[_-]|mailgun\b|/mailgun/",
            "manage": r"manage[_-]|manage\b|/manage/",
            "mantisbt": r"mantisbt[_-]|mantisbt\b|/mantisbt/",
            "matomo": r"matomo[_-]|matomo\b|/matomo/",
            "mautic": r"mautic[_-]|mautic\b|/mautic/",
            "mcafee": r"mcafee[_-]|mcafee\b|/mcafee/",
            "mdb": r"mdb[_-]|mdb\b|/mdb/",
            "memcached": r"memcached[_-]|memcached\b|/memcached/",
            "meteor": r"meteor[_-]|meteor\b|/meteor/",
            "metersphere": r"metersphere[_-]|metersphere\b|/metersphere/",
            "metinfo": r"metinfo[_-]|metinfo\b|/metinfo/",
            "microstrategy": r"microstrategy[_-]|microstrategy\b|/microstrategy/",
            "microweber": r"microweber[_-]|microweber\b|/microweber/",
            "mida": r"mida[_-]|mida\b|/mida/",
            "minio": r"minio[_-]|minio\b|/minio/",
            "mirai": r"mirai[_-]|mirai\b|/mirai/",
            "misconfigured": r"misconfigured[_-]|misconfigured\b|/misconfigured/",
            "mismatched": r"mismatched[_-]|mismatched\b|/mismatched/",
            "mobotix": r"mobotix[_-]|mobotix\b|/mobotix/",
            "moodle": r"moodle[_-]|moodle\b|/moodle/",
            "mpsec": r"mpsec[_-]|mpsec\b|/mpsec/",
            "msmtp": r"msmtp[_-]|msmtp\b|/msmtp/",
            "magento": r"magento[_-]|magento\b|/magento/",
          
            "mariadb": r"mariadb[_-]|mariadb\b|/mariadb/",
            "mongodb": r"mongodb[_-]|mongodb\b|/mongodb/",
            "mysql": r"mysql[_-]|mysql\b|/mysql/",

            # N
            "nagios": r"nagios[_-]|nagios\b|/nagios/",
            "nagios": r"nagios[_-]|nagios\b|/nagios/",
            "natshell": r"natshell[_-]|natshell\b|/natshell/",
            "netis": r"netis[_-]|netis\b|/netis/",
            "netrc": r"netrc[_-]|netrc\b|/netrc/",
            "netsus": r"netsus[_-]|netsus\b|/netsus/",
            "netsweeper": r"netsweeper[_-]|netsweeper\b|/netsweeper/",
            "nextcloud": r"nextcloud[_-]|nextcloud\b|/nextcloud/",
            "nexus": r"nexus[_-]|nexus\b|/nexus/",
            "nodebb": r"nodebb[_-]|nodebb\b|/nodebb/",
            "nopcommerce": r"nopcommerce[_-]|nopcommerce\b|/nopcommerce/",
            "nps": r"nps[_-]|nps\b|/nps/",
            "ntop": r"ntop[_-]|ntop\b|/ntop/",
            "nuuo": r"nuuo[_-]|nuuo\b|/nuuo/",
            "netgear": r"netgear[_-]|netgear\b|/netgear/",
            "nginx": r"nginx[_-]|nginx\b|/nginx/",
            "nacos": r"nacos[_-]|nacos\b|/nacos/",
            "netdata": r"netdata[_-]|netdata\b|/netdata/",

            # O
            "opencart": r"opencart[_-]|opencart\b|/opencart/",
            "openshift": r"openshift[_-]|openshift\b|/openshift/",
            "opsview":r"opsview[_-]|opsview\b|/opsview/",
            "odoo": r"odoo[_-]|odoo\b|/odoo/",
            "office365": r"office365[_-]|office365\b|/office365/",
            "oliver": r"oliver[_-]|oliver\b|/oliver/",
            "opcache": r"opcache[_-]|opcache\b|/opcache/",
            "openbmcs": r"openbmcs[_-]|openbmcs\b|/openbmcs/",
            "opencats": r"opencats[_-]|opencats\b|/opencats/",
            "opencpu": r"opencpu[_-]|opencpu\b|/opencpu/",
            "opencti": r"opencti[_-]|opencti\b|/opencti/",
            "openemr": r"openemr[_-]|openemr\b|/openemr/",
            "openmage": r"openmage[_-]|openmage\b|/openmage/",
            "opensis": r"opensis[_-]|opensis\b|/opensis/",
            "opensns": r"opensns[_-]|opensns\b|/opensns/",
            "openstack": r"openstack[_-]|openstack\b|/openstack/",
            "openvpn": r"openvpn[_-]|openvpn\b|/openvpn/",
            "optilink": r"optilink[_-]|optilink\b|/optilink/",
            "oracle": r"oracle[_-]|oracle\b|/oracle/",
            "orbiteam": r"orbiteam[_-]|orbiteam\b|/orbiteam/",
            "oscommerce": r"oscommerce[_-]|oscommerce\b|/oscommerce/",
            "otobo": r"otobo[_-]|otobo\b|/otobo/",
            "owncloud": r"owncloud[_-]|owncloud\b|/owncloud/",
            "oxid": r"oxid[_-]|oxid\b|/oxid/",
            "open-proxy": r"Open Proxy",
            "ofbiz": r"ofbiz[_-]|ofbiz\b|/ofbiz/",

            # P
            "paloalto": r"paloalto[_-]|palo[_-]alto[_-]|pan[_-]os[_-]|paloalto\b|palo[_-]alto\b|pan[_-]os\b|/paloalto/|/palo[_-]alto/|/pan[_-]os/",
            "checkpoint": r"checkpoint[_-]|checkpoint\b|/checkpoint/",
            "phpmyadmin": r"phpmyadmin[_-]|phpmyadmin\b|/phpmyadmin/",
            "pa11y": r"pa11y[_-]|pa11y\b|/pa11y/",
            "pacsone": r"pacsone[_-]|pacsone\b|/pacsone/",
            "pagekit": r"pagekit[_-]|pagekit\b|/pagekit/",
            "pagespeed": r"pagespeed[_-]|pagespeed\b|/pagespeed/",
            "pagewiz": r"pagewiz[_-]|pagewiz\b|/pagewiz/",
            "panabit": r"panabit[_-]|panabit\b|/panabit/",
            "panasonic": r"panasonic[_-]|panasonic\b|/panasonic/",
            "pantheon": r"pantheon[_-]|pantheon\b|/pantheon/",
            "parallels": r"parallels[_-]|parallels\b|/parallels/",
            "paypal": r"paypal[_-]|paypal\b|/paypal/",
            "pcdn": r"pcdn[_-]|pcdn\b|/pcdn/",
            "pentaho": r"pentaho[_-]|pentaho\b|/pentaho/",
            "permissions": r"permissions[_-]|permissions\b|/permissions/",
            "pghero": r"pghero[_-]|pghero\b|/pghero/",
            "phalcon": r"phalcon[_-]|phalcon\b|/phalcon/",
            "phpbb": r"phpbb[_-]|phpbb\b|/phpbb/",
            "phpinfo": r"phpinfo[_-]|phpinfo\b|/phpinfo/",
            "phpok": r"phpok[_-]|phpok\b|/phpok/",
            "phpstan": r"phpstan[_-]|phpstan\b|/phpstan/",
            "phpunit": r"phpunit[_-]|phpunit\b|/phpunit/",
            "phpwiki": r"phpwiki[_-]|phpwiki\b|/phpwiki/",
            "phpwind": r"phpwind[_-]|phpwind\b|/phpwind/",
            "pictatic": r"pictatic[_-]|pictatic\b|/pictatic/",
            "pinpoint": r"pinpoint[_-]|pinpoint\b|/pinpoint/",
            "piwik": r"piwik[_-]|piwik\b|/piwik/",
            "pmb": r"pmb[_-]|pmb\b|/pmb/",
            "portainer": r"portainer[_-]|portainer\b|/portainer/",
            "pqube": r"pqube[_-]|pqube\b|/pqube/",
            "prestashop": r"prestashop[_-]|prestashop\b|/prestashop/",
            "processmaker": r"processmaker[_-]|processmaker\b|/processmaker/",
            "processwire": r"processwire[_-]|processwire\b|/processwire/",
            "production": r"production[_-]|production\b|/production/",
            "proftpd": r"proftpd[_-]|proftpd\b|/proftpd/",
            "prtg": r"prtg[_-]|prtg\b|/prtg/",
            "pubspec": r"pubspec[_-]|pubspec\b|/pubspec/",
            "puppetdb": r"puppetdb[_-]|puppetdb\b|/puppetdb/",
            "put": r"put[_-]|put\b|/put/",
            "putty": r"putty[_-]|putty\b|/putty/",
            "pyramid": r"pyramid[_-]|pyramid\b|/pyramid/",
            "pyspider": r"pyspider[_-]|pyspider\b|/pyspider/",
            "python": r"python[_-]|python\b|/python/",
            "prestashop": r"prestashop[_-]|prestashop\b|/prestashop/",
            "prometheus": r"prometheus[_-]|prometheus\b|/prometheus/",
            "postgresql": r"postgresql[_-]|postgresql\b|/postgresql/",
            "plastic": r"plastic[_-]|plastic\b|/plastic/",
            
            # Q
            "qcubed": r"qcubed[_-]|qcubed\b|/qcubed/",
            "qdpm": r"qdpm[_-]|qdpm\b|/qdpm/",
            "qihang": r"qihang[_-]|qihang\b|/qihang/",
            "qizhi": r"qizhi[_-]|qizhi\b|/qizhi/",
            "questdb": r"questdb[_-]|questdb\b|/questdb/",
            "qvidium": r"qvidium[_-]|qvidium\b|/qvidium/",
            "qvisdvr": r"qvisdvr[_-]|qvisdvr\b|/qvisdvr/",
            "qianxin": r"qi'anxin[_-]|qianxin[_-]|qi'anxin\b|qianxin\b|/qi'anxin/|/qianxin/",
            "qcube": r"qcube[_-]|qcube\b|/qcube/",

            # R
            "redis": r"redis[_-]|redis\b|/redis/",
            "razer": r"razer[_-]|razer\b|/razer/",
            "rabbitmq": r"rabbitmq[_-]|rabbitmq\b|/rabbitmq/",
            "rainloop": r"rainloop[_-]|rainloop\b|/rainloop/",
            "rconfig": r"rconfig[_-]|rconfig\b|/rconfig/",
            "redash": r"redash[_-]|redash\b|/redash/",
            "redmine": r"redmine[_-]|redmine\b|/redmine/",
            "ricoh": r"ricoh[_-]|ricoh\b|/ricoh/",
            "rocketchat": r"rocketchat[_-]|rocketchat\b|/rocketchat/",
            "roundcube": r"roundcube[_-]|roundcube\b|/roundcube/",
            "ruckus": r"ruckus[_-]|ruckus\b|/ruckus/",
            "ruijie": r"ruijie[_-]|ruijie\b|/ruijie/",
            "redwood": r"redwood[_-]|redwood\b|/redwood/",
            "r-seenet": r"R-SeeNet[_-]|R-SeeNet\b|/R-SeeNet/",
            "rancher": r"rancher[_-]|rancher\b|/rancher/",
            "rails": r"rails[_-]|rails\b|/rails/",
            "ruby": r"ruby[_-]|ruby\b|/ruby/",
            "revealjs": r"revealjs[_-]|revealjs\b|/revealjs/",
            "responsive-filemanager": r"Responsive filemanager[_-]|Responsive filemanager\b|/Responsive filemanager/",

            # S
            "s3cfg": r"s3cfg[_-]|s3cfg\b|/s3cfg/",
            "saia": r"saia[_-]|saia\b|/saia/",
            "samsung": r"samsung[_-]|samsung\b|/samsung/",
            "sangfor": r"sangfor[_-]|sangfor\b|/sangfor/",
            "sar2html": r"sar2html[_-]|sar2html\b|/sar2html/",
            "secnet": r"secnet[_-]|secnet\b|/secnet/",

            "seeyon": r"seeyon[_-]|seeyon\b|/seeyon/",
            "selenium": r"selenium[_-]|selenium\b|/selenium/",
            "selenoid": r"selenoid[_-]|selenoid\b|/selenoid/",
            "sendgrid": r"sendgrid[_-]|sendgrid\b|/sendgrid/",
       
            "seowon": r"seowon[_-]|seowon\b|/seowon/",
            "sequoiadb": r"sequoiadb[_-]|sequoiadb\b|/sequoiadb/",
            "servicenow": r"servicenow[_-]|servicenow\b|/servicenow/",
            "sftp": r"sftp[_-]|sftp\b|/sftp/",
 
            "shopify": r"shopify[_-]|shopify\b|/shopify/",
            "shoppable": r"shoppable[_-]|shoppable\b|/shoppable/",
            "showdoc": r"showdoc[_-]|showdoc\b|/showdoc/",
            "sitecore": r"sitecore[_-]|sitecore\b|/sitecore/",
            "siteminder": r"siteminder[_-]|siteminder\b|/siteminder/",
            "skycaiji": r"skycaiji[_-]|skycaiji\b|/skycaiji/",
            "slack": r"slack[_-]|slack\b|/slack/",
            "smarterstats": r"smarterstats[_-]|smarterstats\b|/smarterstats/",
            "smf": r"smf[_-]|smf\b|/smf/",
            "sms": r"sms[_-]|sms\b|/sms/",
            "solarview": r"solarview[_-]|solarview\b|/solarview/",
            "solarwinds": r"solarwinds[_-]|solarwinds\b|/solarwinds/",
          
            "sonarqube": r"sonarqube[_-]|sonarqube\b|/sonarqube/",
            "sonicwall": r"sonicwall[_-]|sonicwall\b|/sonicwall/",
            "sony": r"sony[_-]|sony\b|/sony/",
            "spectracom": r"spectracom[_-]|spectracom\b|/spectracom/",
            "spidercontrol": r"spidercontrol[_-]|spidercontrol\b|/spidercontrol/",
            "sponip": r"sponip[_-]|sponip\b|/sponip/",
            "sprintful": r"sprintful[_-]|sprintful\b|/sprintful/",
            "square": r"square[_-]|square\b|/square/",
            "squid": r"squid[_-]|squid\b|/squid/",
            "squirrelmail": r"squirrelmail[_-]|squirrelmail\b|/squirrelmail/",
            "ssh": r"ssh[_-]|ssh\b|/ssh/",
            "ssrf": r"ssrf[_-]|ssrf\b|/ssrf/",
            "stackstorm": r"stackstorm[_-]|stackstorm\b|/stackstorm/",
            "steve": r"steve[_-]|steve\b|/steve/",
            "stripe": r"stripe[_-]|stripe\b|/stripe/",
            "suitecrm": r"suitecrm[_-]|suitecrm\b|/suitecrm/",
            "sumowebtools": r"sumowebtools[_-]|sumowebtools\b|/sumowebtools/",
            "supermicro": r"supermicro[_-]|supermicro\b|/supermicro/",
            "svn": r"svn[_-]|svn\b|/svn/",
            "svnserve": r"svnserve[_-]|svnserve\b|/svnserve/",
            "symantec": r"symantec[_-]|symantec\b|/symantec/",
            "symfony": r"symfony[_-]|symfony\b|/symfony/",
            "syncthru": r"syncthru[_-]|syncthru\b|/syncthru/",
            "szhe": r"szhe[_-]|szhe\b|/szhe/",
            "sqlite": r"sqlite[_-]|sqlite\b|/sqlite/",
            "sysaid": r"sysaid[_-]|sysaid\b|/sysaid/",
            "spring": r"spring[_-]|spring\b|/spring/",
          
            "swarm": r"swarm[_-]|swarm\b|/swarm/",
            "splunk": r"splunk[_-]|splunk\b|/splunk/",
            "sugarcrm": r"sugarcrm[_-]|sugarcrm\b|/sugarcrm/",
            "sv3c": r"sv3c[_-]|sv3c\b|/sv3c/",
    
            "shenyu": r"shenyu[_-]|shenyu\b|/shenyu/",
            "socomec": r"socomec[_-]|socomec\b|/socomec/",
            "sourcecodester": r"sosourcecodestergou[_-]|sourcecodester\b|/sourcecodester/",
          

            "sis-informatik": r"SIS Informatik",
            # T
            "teamcity": r"teamcity[_-]|teamcity\b|/teamcity/",
            "tp-link":r"TP-LINK",
            "tyto-sahi": r"tyto sahi[_-]|tyto sahi\b|/tyto sahi/",
            "trend": r"trend[_-]|trend\b|/trend/",
            "trendnet": r"trendnet[_-]|trendnet\b|/trendnet/",
            "tamronos": r"tamronos[_-]|tamronos\b|/tamronos/",
            "tasmota": r"tasmota[_-]|tasmota\b|/tasmota/",
            "tekon": r"tekon[_-]|tekon\b|/tekon/",
            "tekton": r"tekton[_-]|tekton\b|/tekton/",
            "telecom": r"telecom[_-]|telecom\b|/telecom/",
            "testrail": r"testrail[_-]|testrail\b|/testrail/",
            "thinkcmf": r"thinkcmf[_-]|thinkcmf\b|/thinkcmf/",
            "thinkific": r"thinkific[_-]|thinkific\b|/thinkific/",
            "thruk": r"thruk[_-]|thruk\b|/thruk/",
            "tianqing": r"tianqing[_-]|tianqing\b|/tianqing/",
            "tidb": r"tidb[_-]|tidb\b|/tidb/",
            "tiny": r"tiny[_-]|tiny\b|/tiny/",
 
            "tongda": r"tongda[_-]|tongda\b|/tongda/",
   
            "tpshop": r"tpshop[_-]|tpshop\b|/tpshop/",
            "travis": r"travis[_-]|travis\b|/travis/",
            "turbo": r"turbo[_-]|turbo\b|/turbo/",
            "turbocrm": r"turbocrm[_-]|turbocrm\b|/turbocrm/",
            "twig": r"twig[_-]|twig\b|/twig/",
            "twilio": r"twilio[_-]|twilio\b|/twilio/",
            "twitter": r"twitter[_-]|twitter\b|/twitter/",
            "typo3": r"typo3[_-]|typo3\b|/typo3/",
      
            "titi-wiki": r"Tiki Wiki",

            "tbk": r"tbk[_-]|tbk\b|/tbk/",      
            "tarantella": r"tarantella[_-]|tarantella\b|/tarantella/",

            "tensorboard": r"tensorboard[_-]|tensorboard\b|/tensorboard/",      


            # U
            "ueditor": r"ueditor[_-]|ueditor\b|/ueditor/",
            "umbraco": r"umbraco[_-]|umbraco\b|/umbraco/",
            "unifi": r"unifi[_-]|unifi\b|/unifi/",
            "uvdesk": r"uvdesk[_-]|uvdesk\b|/uvdesk/",
            "unomi": r"unomi[_-]|unomi\b|/unomi/",
  
            "ulterius": r"ulterius[_-]|ulterius\b|/ulterius/",

            # V
            "velotismart": r"velotismart[_-]|velotismart\b|/velotismart/",
            "vagrantfile": r"vagrantfile[_-]|vagrantfile\b|/vagrantfile/",
            "ventrilo": r"ventrilo[_-]|ventrilo\b|/ventrilo/",
            "vernemq": r"vernemq[_-]|vernemq\b|/vernemq/",
            "vidyo": r"vidyo[_-]|vidyo\b|/vidyo/",
            "visionhub": r"visionhub[_-]|visionhub\b|/visionhub/",
            "vscode": r"vscode[_-]|vscode\b|/vscode/",
            "vsftpd": r"vsftpd[_-]|vsftpd\b|/vsftpd/",
            "vtiger": r"vtiger[_-]|vtiger\b|/vtiger/",
            "vsphere": r"vsphere[_-]|vsphere\b|/vsphere/",
            "verint": r"verint[_-]|verint\b|/verint/",
            "vmware": r"vmware[_-]|vmware\b|/vmware/",

            # W
            "wavlink": r"wavlink[_-]|wavlink\b|/wavlink/",
            "wapples": r"wapples[_-]|wapples\b|/wapples/",
            "watchguard": r"watchguard[_-]|watchguard\b|/watchguard/",
            "webalizer": r"webalizer[_-]|webalizer\b|/webalizer/",
            "webasyst": r"webasyst[_-]|webasyst\b|/webasyst/",
            "websheets": r"websheets[_-]|websheets\b|/websheets/",
            "webui": r"webui[_-]|webui\b|/webui/",
            "webuzo": r"webuzo[_-]|webuzo\b|/webuzo/",
            "webview": r"webview[_-]|webview\b|/webview/",
            "wgetrc": r"wgetrc[_-]|wgetrc\b|/wgetrc/",
            "wifisky": r"wifisky[_-]|wifisky\b|/wifisky/",
            "wiren": r"wiren[_-]|wiren\b|/wiren/",
            "wooyun": r"wooyun[_-]|wooyun\b|/wooyun/",
            "wpmudev": r"wpmudev[_-]|wpmudev\b|/wpmudev/",
            "wpad-proxy": r"wpad[_-]|wpad\b|/wpad/",
            "wso2": r"wso2[_-]|wso2\b|/wso2/",
            "weblogic": r"weblogic[_-]|weblogic\b|/weblogic/",
            "websphere": r"websphere[_-]|websphere\b|/websphere/",
            "wordpress": r"wordpress[_-]|wordpress\b|/wordpress/|^wp[_-]|^wp\b|\bWP\b",
            "woocommerce": r"woocommerce[_-]|woocommerce\b|/woocommerce/",
            "wirelesshart": r"wirelesshart[_-]|wirelesshart\b|/wirelesshart/",
            # X
            
            "xiaomi": r"xiaomi[_-]|xiaomi\b|/xiaomi/",
         
            "xmlrpc": r"xmlrpc[_-]|xml[_-]rpc[_-]|xmlrpc\b|xml[_-]rpc\b|/xmlrpc/",
            "xnat": r"xnat[_-]|xnat\b|/xnat/",
            "xoops": r"xoops[_-]|xoops\b|/xoops/",
            "winxp": r"xp[_-]|xp\b|/xp/",
            "xinuo": r"xinuo[_-]|xinuo\b|/xinuo/",

            # Y
            "yeswiki": r"yeswiki[_-]|yeswiki\b|/yeswiki/",
            "yonyou": r"yonyou[_-]|yonyou\b|/yonyou/",
            "yousaytoo": r"yousaytoo[_-]|yousaytoo\b|/yousaytoo/",
            "yoast": r"yoast[_-]|yoast\b|/yoast/",
            "yii": r"yii[_-]|yii\b|/yii/",

            # Z
            "zabbix": r"zabbix[_-]|zabbix\b|/zabbix/",
            "zblogcn": r"zblogcn[_-]|zblogcn\b|/zblogcn/",
            "zendesk": r"zendesk[_-]|zendesk\b|/zendesk/",
            "zend": r"zend[_-]|zend\b|/zend/",
            "zentao": r"zentao[_-]|zentao\b|/zentao/",
            "zeroshell": r"zeroshell[_-]|zeroshell\b|/zeroshell/",
            "zimbra": r"zimbra[_-]|zimbra\b|/zimbra/",
            "zoho": r"zoho[_-]|zoho\b|/zoho/",
 
            "zoom": r"zoom[_-]|zoom\b|/zoom/",
            "zope": r"zope[_-]|zope\b|/zope/",
            "zwave": r"zwave[_-]|zwave\b|/zwave/",
            "zipkin": r"zipkin[_-]|zipkin\b|/zipkin/",


            "zyxel": r"zyxel[_-]|zywall[_-]|zyxel\b|zywall\b|/zyxel/|/zywall/",  #
            "zzzcms": r"zzzcms[_-]|zzzphp[_-]|zzzcms\b|zzzphp\b|/zzzcms/|/zzzphp/",  # 将zzzphp也映射到zzzcms
            "zoho-manageengine": r"zoho[_-]manageengine[_-]|manageengine[_-]|zoho[_-]manageengine\b|manageengine\b|/zoho[_-]manageengine/|/manageengine/",
            "z-blog":  r"z-blog[_-]|z-blog\b|/z-blog/",
            
            
            
             
            
            
            
            
            
            
        }

 
        self.ignore_terms = {
            'unauthenticated',
            'authenticated',
            'unauthorized',
            'authorized',
            'remote',
            'local',
            'arbitrary',
            'disclosure',
            'injection',
            'bypass',
            'default',
            'weak',
            'missing',
            'exposed',
            'sensitive',
            'information',
            'disclosure',
            'enterprise',
            "server",
            'detection'
        }

    def need_update(self):
        """检查是否需要更新模板"""
        try:
           
            if not os.path.exists(self.classified_templates):
                print("Classified templates directory not found, need classification.")
         
                if os.path.exists(self.nuclei_templates):
                 
                    mtime = os.path.getmtime(self.nuclei_templates)
                    last_update = datetime.fromtimestamp(mtime)
                    now = datetime.now()
                    
                    if (now - last_update) <= timedelta(days=self.update_interval):
                        print(f"Templates are up to date (last update: {last_update})")
                        return False
                return True
            
            # 检查nuclei_templates目录
            if not os.path.exists(self.nuclei_templates):
                print("Templates directory not found, need download.")
                return True
            
            # 检查更新时间
            mtime = os.path.getmtime(self.nuclei_templates)
            last_update = datetime.fromtimestamp(mtime)
            now = datetime.now()
            
            if (now - last_update) > timedelta(days=self.update_interval):
                print(f"Templates are older than {self.update_interval} days, need update.")
                return True
            
            print(f"Templates are up to date (last update: {last_update})")
            return False
            
        except Exception as e:
            print(f"Error checking update: {e}")
            return True

    def download_templates(self):
        """下载最新的模板"""
        try:
            print("Downloading nuclei templates...")
            response = requests.get(self.download_url, stream=True)
            response.raise_for_status()
            
            if os.path.exists(self.nuclei_templates):
                shutil.rmtree(self.nuclei_templates)
            
            with zipfile.ZipFile(BytesIO(response.content)) as zip_ref:
                zip_ref.extractall()
                extracted_dir = "nuclei-templates-master"
                if os.path.exists(extracted_dir):
                    os.rename(extracted_dir, self.nuclei_templates)
                    
            print("Templates downloaded successfully")
            return True
            
        except Exception as e:
            print(f"Error downloading templates: {e}")
            return False

    def classify_template(self, template_path):
        """根据组件模式分类模板"""
        try:
            if not isinstance(template_path, str):
                template_path = str(template_path)
            
            file_str = template_path.lower()
            file_name = Path(template_path).stem.lower()
            
            # 1. 首先尝试从文件名中提取实际的产品/组件名称
            name_parts = file_name.split('-')
            
            # 找到第一个不在 ignore_terms 中的部分作为可能的组件名
            potential_component = None
            for part in name_parts:
                part = part.strip()
                if part and part not in self.ignore_terms:
                    potential_component = part
                    break
            
            if potential_component:
                # 检查这个潜在组件是否匹配任何已知组件
                sorted_components = sorted(self.component_patterns.items(), 
                                        key=lambda x: len(x[0]), 
                                        reverse=True)
                
                for component, pattern in sorted_components:
                    if re.search(pattern, potential_component, re.I):
                        return component
            
            # 2. 如果没有找到匹配，继续使用现有的匹配逻辑
            # ... [保持原有的其他匹配逻辑] ...

            # 2. 继续原有的匹配逻辑
            name_parts = file_name.split('-')[0].split('_')[0]
            
            sorted_components = sorted(self.component_patterns.items(), 
                                     key=lambda x: len(x[0]), 
                                     reverse=True)
            
            # 1. 首���检查文件名中的组件
            for component, pattern in sorted_components:
                if name_parts.startswith(component):
                    return component
            
            # 2. 如果文件名没有匹配到，尝试读取yaml内容
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    content = yaml.safe_load(f)
                    if content and isinstance(content, dict):
                        template_id = content.get('id', '').lower()
                        info = content.get('info', {})
                        if isinstance(info, dict):
                            name = info.get('name', '').lower()
                            
                            # 3. ���查id和name是否匹配任何组件
                            for component, pattern in sorted_components:
                                try:
                                    if re.search(pattern, template_id, re.I) or re.search(pattern, name, re.I):
                                        return component
                                except re.error:
                                    continue
            except Exception as e:
                print(f"Error reading yaml content from {template_path}: {e}")
            
            # 4. 如果文件路径没有匹配到，再检查完整路径
            for component, pattern in sorted_components:
                try:
                    if re.search(rf"\b{component}\b", file_str, re.I):  # 使用单词边界
                        return component
                except re.error:
                    print(f"Invalid regex pattern for component {component}: {pattern}")
                    continue
                except Exception as e:
                    print(f"Error matching pattern for component {component}: {e}")
                    continue
                
            # 如果没有匹配到任何组件，返回others
            return "others"
            
        except Exception as e:
            print(f"Error classifying template {template_path}: {e}")
            return "others"

    def analyze_others_templates(self):
 
        others_path = os.path.join(self.classified_templates, 'others')
        if not os.path.exists(others_path):
            return
        
        others_count = 0
        potential_components = set()
        
        for root, dirs, files in os.walk(others_path):
            yaml_files = [f for f in files if f.endswith(('.yml', '.yaml'))]
            others_count = len(yaml_files)
            
            for yaml_file in yaml_files:
                template_path = os.path.join(root, yaml_file)
                try:
                    with open(template_path, 'r', encoding='utf-8') as f:
                        template_data = yaml.safe_load(f)
                        if template_data and isinstance(template_data, dict):
                            template_id = template_data.get('id', '')
                            info = template_data.get('info', {})
                            if isinstance(info, dict):
                                name = info.get('name', '')
                                
                                # 获取id和name的第一个单词
                                id_first_word = template_id.split('-')[0].lower() if template_id else ''
                                name_first_word = name.split()[0].lower() if name else ''
                                
                                # 如果两个词相同且不为空
                                if id_first_word and id_first_word == name_first_word:
                                    component_name = id_first_word
                                    pattern = f'"{component_name}": r"{component_name}[_-]|{component_name}\\b|/{component_name}/",'
                                    potential_components.add(pattern)
                                
                except Exception as e:
                    print(f"Error analyzing template {yaml_file}: {e}")
        
        # 打印分析结果
        print("\n=== Others Analysis ===")
        print("-" * 50)
        print(f"Total templates in others: {others_count}")
        
        if potential_components:
            print("\nPotential new component patterns:")
            print("Add these to component_patterns:")
            for pattern in sorted(potential_components):
                print(pattern)
        else:
            print("\nNo potential new components identified.")

    def should_filter_template(self, yaml_file):
        """检查模板是否需要过滤"""
        # 过滤特定文件
        filtered_files = {
            'wappalyzer-mapping.yml',
            'wappalyzer-mapping.yaml',
            ".pre-commit-config.yml",
            "system-properties-exposure.yaml",
            "CVE-2019-3403.yaml"
        }
        
        # 检查文件名是否在过滤列表中
        if yaml_file.name.lower() in filtered_files:
            return True
        
        # 检查文件名是否包含detect
        if 'detect' in yaml_file.stem.lower():
            return True
        
        # 读取yaml内容检查
        try:
            with yaml_file.open('r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                if content and isinstance(content, dict):
                    info = content.get('info', {})
                    if isinstance(info, dict):
                        # 检查severity是否为info
                        if info.get('severity') == 'info':
                            return True
                        
                        # 检查info.name或classification是否包含detect
                        name = info.get('name', '').lower()
                        classification = info.get('classification', {})
                        if isinstance(classification, dict):
                            cvss_metrics = classification.get('cvss-metrics', '').lower()
                            cve_id = classification.get('cve-id', '').lower()
                            if 'detect' in name or 'detect' in cvss_metrics or 'detect' in cve_id:
                                return True
        except Exception as e:
            print(f"Error reading yaml file {yaml_file}: {e}")
            return True  # 如果读取出错,也过滤掉
        
        return False
    def clean_component_name(self, name):
        """清理组件名称"""
        if not name:
            return name
            
        # 1. 移除版本号相��内容
        name = re.sub(r'[<>]=?\s*\d+(\.\d+)*', '', name)  # 移除 <,>,<=,>= 版本号
        name = re.sub(r'\s+v?\d+(\.\d+)*', '', name)      # 移除普通版本号
        
        # 2. 基本清理
        name = name.strip().lower()                        # 转小写并去除首尾空格
        name = re.sub(r'\s+', '-', name)                  # 空格转连字符
        name = re.sub(r'[^a-z0-9-]', '', name)           # 只保留字母数字和连字符
        name = re.sub(r'-+', '-', name)                   # 多个连字符合并
        name = name.strip('-')                            # 去除首尾连字符
    
        return name
    def get_component_from_yaml(self, yaml_file):
        """从yaml内容中提取组件名"""
        try:
            with yaml_file.open('r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                if not content or not isinstance(content, dict):
                    return None
                
                # 检查severity
                info = content.get('info', {})
                if isinstance(info, dict) and info.get('severity') == 'info':
                    return 'filtered'
                
                template_id = content.get('id', '').lower()
                name = info.get('name', '').lower() if isinstance(info, dict) else ''
                
                # 如果是CVE ID，尝试从name中提取组件名
                if template_id.startswith('cve-'):
                    if name:
                        if name:
                            # 取第一个分隔符前的部分作为组件名
                            for sep in ['-', ' - ', ' ', ':']:
                                if sep in name:
                                    component = name.split(sep)[0]
                                    component = self.clean_component_name(component)
                                    if component:
                                        return component
                        
                # 原有的组件名提取逻辑
                component_patterns = []
                if template_id and not template_id.startswith('cve-'):
                    component_patterns.append(template_id.split('-')[0])
                if name:
                    component_patterns.append(name.split()[0])
                
                for pattern in component_patterns:
                    if pattern and not any(c in pattern for c in '- _/\\'):
                        return pattern
                    
        except Exception as e:
            print(f"Error reading yaml file {yaml_file}: {e}")
        return None

    def log_new_component_mapping(self, template_id, original_name, component, filename):
     
        root_dir = os.path.dirname(os.path.dirname(__file__))
        log_file = Path(root_dir) / "classified_templates" / "new_components_mapping.md"
        
   
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 追加写入映射关系
        with log_file.open('a', encoding='utf-8') as f:
            f.write(f"- {template_id}: {original_name} -> {component}\n")
            f.write(f"  Filename: {filename}\n")
            f.write("\n")

    def organize_templates(self):
       
        classified_path = Path(self.classified_templates)
        if classified_path.exists():
            shutil.rmtree(classified_path)
        classified_path.mkdir(parents=True, exist_ok=True)
        
        stats = defaultdict(int)
        new_components = defaultdict(list)  
        total_files = 0
        filtered_files = 0
        valid_files = 0
        others_count = 0
        
        # 定义要过滤的目录
        filtered_dirs = {'.github', 'cnvd'}
        
        # 遍历所有yaml文件
        nuclei_path = Path(self.nuclei_templates)
        for yaml_file in nuclei_path.rglob("*.y*ml"):
            total_files += 1
            
            # 检查是否在过滤目录中
            if any(filtered_dir in yaml_file.parts for filtered_dir in filtered_dirs):
                filtered_files += 1
                continue
            
            # 检查是否需要过滤detect相关模板
            if self.should_filter_template(yaml_file):
                filtered_files += 1
                continue
            
            try:
                # 首先尝试基于文件名分类
                component = self.classify_template(str(yaml_file.absolute()))
                
                # 如果分类为others，尝试从yaml内容中提取组件
                if component == "others":
                    yaml_component = self.get_component_from_yaml(yaml_file)
                    if yaml_component:
                        if yaml_component == 'filtered':
                            filtered_files += 1
                            continue
                        component = yaml_component
                        # 记录新发现的组件及其模板
                        new_components[component].append(yaml_file.name)
                
                if component == "others":
                    others_count += 1
                
                # 创建组件目录
                component_dir = classified_path / component
                component_dir.mkdir(exist_ok=True)
                
                # 复制文件到对应组件目录
                dst_file = component_dir / yaml_file.name
                shutil.copy2(yaml_file, dst_file)
                stats[component] += 1
                valid_files += 1
                
            except Exception as e:
                print(f"Error processing {yaml_file.name}: {e}")
                filtered_files += 1
                continue

        # 生成统计信息
        stats_md = classified_path / "poc_stats.md"
        with stats_md.open("w", encoding="utf-8") as f:
            f.write("# POC Classification Statistics\n\n")
            
            f.write("## Overall Statistics\n\n")
            f.write(f"- Total files processed: {total_files}\n")
            f.write(f"- Filtered files: {filtered_files}\n")
            f.write(f"- Valid templates: {valid_files}\n")
            f.write(f"- Unclassified templates (others): {others_count}\n")
            f.write(f"- Total components: {len(stats)}\n\n")
            
            f.write("## Component Statistics\n\n")
            f.write("| Component | Templates Count |\n")
            f.write("|-----------|----------------|\n")
            for component, count in sorted(stats.items(), key=lambda x: (-x[1], x[0])):
                if component != "others":
                    f.write(f"| {component} | {count} |\n")
            
            if "others" in stats:
                f.write(f"| others | {stats['others']} |\n")
            
            # 添加新发现的组件信息
            if new_components:
                f.write("\n## Newly Discovered Components\n\n")
                for component, templates in sorted(new_components.items()):
                    f.write(f"\n### {component}\n")
                    f.write(f"Templates count: {len(templates)}\n\n")
                    f.write("Templates:\n")
                    for template in sorted(templates):
                        f.write(f"- {template}\n")
        
        # 打印简要统计到控制台
        print("\n=== Classification Summary ===")
        print(f"Total files processed:      {total_files:5}")
        print(f"Filtered files:            {filtered_files:5}")
        print(f"Valid templates:           {valid_files:5}")
        print(f"Unclassified templates:    {others_count:5}")
        print(f"Total components:          {len(stats):5}")
        print(f"\nNewly discovered components: {len(new_components)}")
        print(f"Detailed statistics saved to: {stats_md}")

def main():
    classifier = NucleiTemplateClassifier()
    if classifier.need_update():
        if classifier.download_templates():
            classifier.organize_templates()
    else:
        classifier.organize_templates()

if __name__ == "__main__":
    main()
 