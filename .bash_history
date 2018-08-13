kubectl get secret -n contrail | grep kubemanager
kubectl describe secret contrail-kubemanager-token-vsksb -n contrail | grep "token:" | awk '{print $2}'
ls
mkdir install_scripts
ls
mv 02-patch-ansible-playbook install_scripts/
ls
mb 05-copy-required-files install_scripts/
mv 05-copy-required-files 
mv 05-copy-required-files install_scripts/
ls
mv 13-run-contrail-install-playbook install_scripts/
ls
mv k8s-dashboard.yaml install_scripts/
ls
rm -rf all-in-one/
ls
rm web-dev.yaml.sav 
rm policy-web-to-app.yaml.sav 
ls
cd tests/
ls
cd ..
mv -r tests/ /tmp/
mv tests/ /tmp/
ls
cd k8s_files/
ls
cd ..
ls
cd vmx/
ls
cd library/
ls
cd ..
ls
cd files/
ls
cd ..
cd tasks/
ls
cat main.yaml 
cd ..
ls
cd templates/
ls
cat base.conf.j2 
ls
cd ..
ls
cd tasks/
ls
cat main.yaml 
cd 
l
ls
scp -r vmx stella@172.27.224.11:/Users/stella/Desktop/mPSK
ping 172.27.224.11
ls
cd k8s_files/
ls
cd namespaces_isolation/
ls
cat juniper-iso.yaml 
ls
cat ubuntu-iso.pod.yaml 
cd ..
ls
cd ..
ls
ping 192.168.1.101
ls
cd k8s_files/
ls
cat ubuntu-a.pod.yaml 
ls
cd ubuntu-green.pod.yaml 
cat ubuntu-green.pod.yaml 
ls
cd namespaces_isolation/
ls
cat ubuntu-iso.pod.yaml 
ls
cat ubuntu-iso1.pod.yaml 
ls
cp ubuntu-iso1.pod.yaml ubuntu-yellow.pod.yaml
vi ubuntu-yellow.pod.yaml 
cat ubuntu-yellow.pod.yaml 
lsc
ls
cat ubuntu-iso1.pod.yaml 
ls
cd ..
ls
cat ubuntu-green.pod.yaml 
ls
cd namespaces_isolation/
ls
kubectl create -f ubuntu-yellow.pod.yaml 
kubectl get pods --all-namespaces
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-yellow   
kubectl create -f ubuntu-yellow.pod.yaml  -n juniper-iso
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-yellow -n juniper-iso ping 192.168.2.3
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-yellow -n juniper-iso ping 192.168.2.3
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-yellow -n juniper-iso ping 10.47.255.251
kubectl exec -ti ubuntu-iso1 -n juniper-iso ping 10.47.255.251
kubectl exec -ti ubuntuiso1 -n juniper-iso ping 10.47.255.251
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.251
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.250
kubectl exec -ti ubuntuiso -n juniper-iso bash
ls
[root@master namespaces_isolation]# 
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.250
ls
cp juniper-iso.yaml juniper-iso2.yaml 
vi juniper-iso2.yaml 
kubectl create -f juniper-iso2.yaml 
kubectl get namespaces
ls
cp ubuntu-iso.pod.yaml ubuntu-iso2.pod.yaml 
vi ubuntu-iso2.pod.yaml 
kubectl create -f ubuntu-iso2.pod.yaml -n juniper-iso2
kubectl get pods --all-namespaces -o wide
kubectl exec -it ubuntuiso2 -n juniper-iso2 ping 10.47.255.251
kubectl exec -it ubuntuiso2 -n juniper-iso2 ping 10.47.255.250
kubectl exec -it ubuntuiso2 -n juniper-iso2 ping 10.47.255.249
kubectl exec -it ubuntuiso2 -n juniper-iso2 ping 10.47.255.250
ls
contrail-status
kubectl get nodes
kubectl get pods --all-namespaces
docker ps
kubectl get nodes
contrail-status
docker ps
docker ps | grep alarm-gen
docker stop analytics_alarm-gen_1
docker start analytics_alarm-gen_1
docker ps | grep api
contrail-status
kubectl get pods --all-namespaces
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso2 ping 10.47.255.251
kubectl exec -ti ubuntuiso2 -n juniper-iso2 ping 10.47.255.251
kubectl exec -ti ubuntuiso2 -n juniper-iso2 ping 10.47.255.247
ls
cd k8s_files/
ls
cd namespaces_isolation/
ls
cp ubuntu-iso2.pod.yaml ubuntu-iso3.pod.yaml
vi ubuntu-iso3.pod.yaml 
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.248
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.25
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.250
kubectl get namespaces
kubectl get pods --all-namespaces -o wide
kubectl delete pods -n ubuntuiso2 juniper-iso2 
kubectl delete pods ubuntuiso2 -n juniper-iso2 
kubectl delete namespaces juniper-iso2
kubectl get namespaces
kubectl delete pods ubuntu-yellow  -n juniper-iso 
kubectl delete pods ubuntuiso  -n juniper-iso 
kubectl delete pods ubuntuiso1  -n juniper-iso 
kubectl get pods --all-namespaces -o wide
kubectl get namespaces
kubectl delete namespaces juniper-iso
la
kubectl get namespaces
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-blue  -n juniper2
kubectl delete namespaces juniper2
kubectl get namespaces
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-green -n juniper
kubectl delete pods ubuntu-red -n juniper
kubectl delete pods ubuntu-a -n juniper
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-b -n juniper
kubectl get pods --all-namespaces -o wide
kubectl get namespaces
kubectl delete namespaces juniper
kubectl get namespaces
cd ..
ls
kubectl create namespaces juniper
kubectl create namespace juniper
kubectl get namespaces
ls
kubectl create -f ubuntu-a.pod.yaml -n juniper
kubectl get pods -n juniper -o wide
kubectl create namespace juniper2
ls
kubectl create -f ubuntu-b.pod.yaml -n juniper2
kubectl get pods -n juniper2 -o wide
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.250 
ls
cd namespaces_isolation/
ls
cat juniper-iso.yaml 
kubectl create -f juniper-iso.yaml 
kubectl create -f juniper-iso.yaml
ls
car ubuntu-iso.pod.yaml 
cat ubuntu-iso.pod.yaml 
kubectl create -f ubuntu-iso.pod.yaml -n juniper-iso
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.251
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.249
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.252
cd ..
ls
cat ubuntu-a.pod.yaml 
cat ubuntu-b.pod.yaml 
ls
cd namespaces_isolation/
ls
cat juniper-iso.yaml 
cat ubuntu-iso.pod.yaml 
ls
cat ubuntu-iso.pod.yaml 
kubectl get pods --all-namespaces -o wide
kubectl describe pods ubuntuiso -n NAMESPACE     NAME                                    READY     STATUS    RESTART
juniper-iso
kubectl describe pods ubuntuiso -n juniper-iso
cat ubuntu-iso.pod.yaml 
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.251
kubectl describe namespaces juniper-iso
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.250
ls
cd ..
ls
cat ubuntu-a.pod.yaml 
vi pod.yaml
kubectl create -f pod.yaml 
vi pod.yaml
kubectl create -f pod.yaml 
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.248
kubectl exec -ti ubuntuiso -n juniper-iso bash
kubectl get pods --all-namespaces -o wide
kubectl delete pods  ghost
kubectl delete pods  ubuntuiso  -n juniper-iso
kubectl delete namespaces Contrail CNI plugin
kubectl delete namespaces 
kubectl delete namespaces [root@master k8s_files]# kubectl delete pods  ubuntuiso  -n 
kubectl delete namespaces juniper-iso
kubectl get pods --all-namespaces -o wide
kubectl get namespaces
ls
cd namespaces_isolation/
ls
kubectl create -f juniper-iso.yaml 
ls
kubectl get namespaces
ls
cd ..
ls
kubectl create -f pod.yaml -n juniper-iso
kubectl get pods --all-namespaces -o wide
kubectl describe namespace juniper-iso
kubectl describe pods ghost  -n juniper-iso
kubectl exec -ti ghost -n juniper-iso ping 10.47.255.248
kubectl delete pods ghost  -n juniper-iso
kubectl get pods --all-namespaces -o wide
ls
cd namespaces_isolation/
ls
kubectl create -f ubuntu-iso.pod.yaml -n juniper-iso
kubectl exec -ti ghost -n juniper-iso ping 10.47.255.248
kubectl get pods --all-namespaces -o wide
kubectl exec -ti pods ubuntuiso -n juniper-iso  ping  10.47.255.251 
kubectl exec -ti ubuntuiso -n juniper-iso  ping  10.47.255.251 
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.251 
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.251 -n juniper
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.251 
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso ping 10.47.255.250
cd /etc/
ls
cd contrail/
ls
kubectl get pods --all-namespaces -o wide
kubectl describe pods ubuntu-a -n juniper
cd /var/run/secrets/kubernetes.io
ls
cd
kubectl get pods --all-namespaces -o wide
cd k8s_files/
ls
cd namespaces_isolation/
ls
kubectl create pods ubuntu-iso1.pod.yaml -n juniper-iso
kubectl create -f ubuntu-iso1.pod.yaml -n juniper-iso
curl http://127.0.0.1:9091/vm-cfg/7d187eff-8e3a-11e8-8890-000c2957cc52
kubectl create pods ubuntu-iso1.pod.yaml -n juniper-iso
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso1 -n juniper-iso ping 10.47.255.249
kubectl exec -ti ubuntuiso1 -n juniper-iso ping 10.47.255.250
ls
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso1 -n juniper-iso bash
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-a -n juniper bash
kubectl exec -ti ubuntuiso1 -n juniper-iso bash
kubectl exec -ti ubuntu-a -n juniper bash
kubectl exec -ti ubuntuiso1 -n juniper-iso ping 10.47.255.251
contrail-status
curl 172.27.10.42:8081/analytics/virtual-network/default-domain
curl 172.27.10.42:8081/analytics/virtual-network
curl 172.27.10.42:8081/analytics/
curl 172.27.10.41:8081/analytics/
curl 172.27.10.42:8081/analytics/
curl 172.27.10.42:8081
docker ps
docker ps | grep analytics-api
docker exex -ti analytics_api_1 bash
docker exec -ti analytics_api_1 bash
ls
docker ps
docker ps | grep api
docker exec -ti config_api_1
docker exec -ti config_api_1 bash
ls
kubectl get all --all-namespaces
kubectl get svc
kubectl get pods --all-namespaces -o wide
kubectl exec -ti   ubuntuiso -n  juniper-iso ping  10.47.255.251
kubectl exec -ti   ubuntuiso1 -n  juniper-iso ping  10.47.255.251
ls
cd ..
ls
kubectl exec -ti   ubuntuiso1 -n  juniper-iso ping  10.47.255.251
kubectl exec -ti   ubuntuiso1 -n  juniper-iso ping  10.47.255.250
kubectl get pods --all-namespaces -o wide
kubectl create -f ubuntu-green.pod.yaml -n juniper
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-green -n juniper
kubectl create -f ubuntu-green.pod.yaml -n juniper
kubectl get pods --all-namespaces -o wide
kubectl describe namespaces juniper-iso
ping contrailk8s.juniper.net
ping http://master.contrailk8s.juniper.net/
ping master.contrailk8s.juniper.net
ls
cat ubuntu-a.pod.yaml 
cat ubuntu-green.pod.yaml 
ls
cd  /etc/contrail/
ls
cd
cd k8s_files/
ls
cat ubuntu-green.pod.yaml 
contrailctl
kubectl get nodes
docker ps
contrail-status
cat /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
kubectl get secret -n contrail | grep kubemanager
kubectl describe secret contrail-kubemanager-token-vsks  -n contrail | grep "token:" | awk '{print $2}'
ls
cd contrail-ansible-deployer/
ls
cd playbooks/
ls
cd ..
ls
cd /mnt/
ls
cat 03-update-instances-yaml 
cat 06-disable-selinux 
cd
cd contrail-ansible-deployer/config/all_hosts 
cat contrail-ansible-deployer/config/all_hosts
vi contrail-ansible-deployer/config/all_hosts
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntuiso -n juniper-iso 
kubectl delete pods ubuntuiso1 -n juniper-iso 
kubectl delete pods ubuntu-a -n juniper
kubectl delete pods ubuntu-green -n juniper
kubectl delete pods ubuntu-b -n juniper2
kubectl get pods --all-namespaces -o wide
kubectl get namespaces
kubectl delete namespaces juniper
kubectl delete namespaces juniper2
kubectl delete namespaces juniper-iso
kubectl get namespaces
kubectl create namespaces juniper
kubectl create namespace juniper
ls
cd k8s_files/
ls
cd namespaces_isolation/
ls
kubectl create -f juniper-iso2.yaml
kubectl create namespace juniper-iso
kubectl get namespaces
kubectl delete namespaces juniper-iso
kubectl delete namespaces juniper-iso2
kubectl delete namespaces juniper
kubectl delete namespaces juniper-iso2
kubectl delete namespaces juniper-iso
kubectl create namespace juniper-iso
kubectl delete namespaces juniper-iso
kubectl create -f juniper-iso.yaml
kubectl get namespaces
kubectl delete namespaces juniper-iso
kubectl create -f juniper-iso.yaml
kubectl get namespaces
kubectl delete namespaces juniper-iso
ls
cat juniper-iso2.yaml 
kubectl create -f juniper-iso2.yaml
kubectl create namespace juniper-iso
kubectl get namespaces
kubectl get namespaces -o wide
kubectl delete namespaces juniper-iso
kubectl create namespace juniper
cd ..
;s
kubectl create namespace juniper2
ls
kubectl create -f ubuntu-a.pod.yaml -n juniper
kubectl create -f ubuntu-b.pod.yaml -n juniper
cat ubuntu-b.pod.yaml 
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-a ping 10.47.255.250 
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.250 
ls
cat ubuntu-green.pod.yaml 
kubectl create -f ubuntu-green.pod.yaml -n juniper
kubectl create -f ubuntu-red.pod.yaml -n juniper
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-green -n juniper ping 10.47.255.250
kubectl exec -ti ubuntu-green -n juniper ping 192.168.2.3
kubectl create -f ubuntu-blue.pod.yaml -n juniper2
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-green -n juniper ping 192.168.3.3
kubectl exec -ti ubuntu-red -n juniper ping 192.168.3.3
ls
cd namespaces_isolation/
ls
cat ubuntu-yellow.pod.yaml 
vi ubuntu-yellow.pod.yaml 
ls
cat ubuntu-iso.pod.yaml 
kubectl create -f ubuntu-iso.pod.yaml -n juniper-iso2
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso2 ping 10.47.255.251
ls
cat ubuntu-yellow.pod.yaml 
kubectl create -f ubuntu-yellow.pod.yaml -n juniper-iso2
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-yellow -n juniper-iso2 ping 192.168.1.3
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-yellow  -n juniper-iso2
kubectl delete pods ubuntuiso  -n juniper-iso2
kubectl get pods --all-namespaces -o wide
kubectl delete namespaces juniper-iso2
kubectl get namespaces 
ls
cat juniper-iso.yaml 
ls
cp juniper-iso2.yaml juniper-iso3.yaml 
vi juniper-iso3.yaml 
kubectl create -f juniper-iso3.yaml 
vi juniper-iso3.yaml 
kubectl create -f juniper-iso3.yaml 
kubectl get namespaces 
kubectl create -f juniper-iso2.yaml 
ls
vi ubuntu-iso.pod.yaml 
kubectl create -f ubuntu-iso.pod.yaml -n juniper-iso3
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntuiso -n juniper-iso3 ping 10.47.255.251
kubectl delete pods  ubuntuiso  -n juniper-iso3
kubectl delete namespaces juniper-iso3
kubectl get namespaces
kubectl delete namespaces juniper-iso2
kubectl get namespaces
kubectl get pods --all-namespaces -o wide
kubectl delete pods  ubuntu-a  -n juniper
kubectl delete pods  ubuntu-b  -n juniper
kubectl delete pods  ubuntu-green  -n juniper
kubectl delete pods  ubuntu-red  -n juniper
kubectl get pods --all-namespaces -o wide
kubectl delete namespaces juniper
kubectl get pods --all-namespaces -o wide
kubectl delete pods  ubuntu-blue  -n juniper2
kubectl get pods --all-namespaces -o wide
kubectl delete namespaces juniper2
kubectl get pods --all-namespaces -o wide
kubectl get namespaces
ls
cat juniper-iso3.yaml 
kubectl config view
docker exec -it kubemanager_kubemanager_1 bash
kubectl get pods --all-namespaces -o wide
ls
cd k8s_files/
ls
kubectl create namespace test_service
kubectl create namespace testservice
ls
kubectl create -f ubuntu-a.pod.yaml  -n testservice
kubectl get pods --all-namespaces -o wide
kubectl create -f ubuntu-b.pod.yaml  -n testservice
kubectl get pods --all-namespaces -o wide
kubectl create namespace testservice2
kubectl create -f ubuntu-b.pod.yaml  -n testservice2
kubectl get pods --all-namespaces -o wide
mkdir service
cd service/
vi deny_ingress
ls
kubectl create -f deny_ingress -n testservice
kubectl get svc
kubectl get svc -n testservice
kubectl get networkpolicy
kubectl get networkpolicy -n testservice
kubectl get networkpolicy
kubectl get networkpolicy -n testservice
kubectl get pods --all-namespaces -o wide
kubectl exec -ti                                1/1       Running   0          3m        10.47.255.250   worker1
kubectl exec -ti ubuntu-b -n testservice2 ping 10.47.255.250
kubectl exec -ti ubuntu-b -n testservice ping 10.47.255.249
kubectl exec -ti ubuntu-a -n testservice ping 10.47.255.249
kubectl exec -ti ubuntu-b -n testservice2 ping 10.47.255.251
kubectl exec -ti ubuntu-b -n testservice2 ping 10.47.255.249
ls
pwd
ls
cat deny_ingress 
oc get pods
kubectl get pods 
kubectl get pods --all-namespaces
kubectl describe pods ubuntu-a -n testservice
kubectl describe namespace
kubectl get pods --all-namespaces
kubectl exec ubuntuiso bash 
kubectl exec ubuntuiso bash -n juniper-iso2
kubectl get nodes
kubectl describe nodes worker1
kubectl get pods 
kubectl get pods --all-namespaces
kubectl get pods ubuntuiso -n juniper-iso2
kubectl describe pods ubuntuiso -n juniper-iso2
kubectl edit pods ubuntuiso -n juniper-iso2
kubectl get pods --all-namespaces
kubectl exec -it ubuntuiso -n juniper-iso2 bash
kubectl exec -it ubuntu-a -n juniper bash
kubectl describe namespaces
kubectl get pods -o wide
kubectl get pods --all-namespaces -o wide
kubectl exec -it ubuntu-a -n testservice bash
kubectl exec -it ubuntuiso -n juniper-iso2 bash 
kubectl exec -it ubuntu-a -n juniperbash
kubectl exec -it ubuntu-a -n juniper bash
kubectl get pods --all-namespaces -o wide
kubectl exec -it ubuntu-a -n juniper bash
kubectl exec -it ubuntuiso -n juniper-iso2 bash 
kubectl get namespaces 
kubectl describe ns
kubectl edit ns juniper-iso2 
ll
ll k8s_files/
docker ps -a
cat /etc/contrailctl/kubemanager.conf 
ls
kubectl get svc --all-namespaces
kubectl get networkpolicy  --all-namespaces
kubectl describe testservice 
kubectl describe networkpolicy testservice
kubectl describe networkpolicy default-deny
kubectl describe networkpolicy default-deny -n testservice
ls
cd k8s_files/
ls
cd service/
ls
cat deny_ingress 
docker ps
docker ps | grep kube
contrail-status
more /etc/contrail/kubemanager/
cd /etc/contrail/kubemanager/
ls
cat docker-compose.yaml 
cd ..
.s
ls
cat common.env 
ls
cat common_analytics.env 
cd config
ls
cd ..
ls
cd redis/
ls
cat docker-compose.yaml 
cd ..
ls
cd kubemanager/
ls
cat docker-compose.yaml 
cd ..
ls
cd compose/
ls
cd ..
ls
cd webui/
ls
cat docker-compose.yaml 
cd ..
;s
ls
cd config_database/
ls
cat docker-compose.yaml 
cd ..
ls
cat contrail-kubemanager-serviceaccount.yaml 
ls
cd ssl/
ls
cd ..
ls
cd ..
ls
cd kubernetes/
ls
cat controller-manager.conf 
cd ..
ls
cd kubernetes/
ls
cd pki/
ls
cd ..
ls
cat controller-manager.conf 
cd ..
ls
cd contrail/
pwd
cd ..
cd kubernetes/
ls
pwd
contrail-statis
contrail-status
ls
cd
ls
cd k8s_files/
ls
pwd
ls
cd
cd k8s_files/
ls
cd namespaces_isolation/
ls
cat juniper-iso2.yaml 
kubectl create -f juniper-iso2.yaml 
ls
cat ubuntu-iso.pod.yaml 
kubectl create of ubuntu-iso.pod.yaml -n juniper-iso2
kubectl create -f ubuntu-iso.pod.yaml -n juniper-iso2
kubectl get pods --all-namespaces -o wide
kubectl create namespace juniper
kubectl get namespaces
cd ..
ls
kubectl create -f ubuntu-a.pod.yaml -n juniper
kubectl get pods --all-namespaces -o wide
ls
kubectl exec -ti ubuntuiso -n juniper-iso2 ping 10.47.255.247

ls
cd
ls
cd /mnt/
ls
cat 18-create-test-network-and-vm 
ls
cat 06-disable-selinux 
cd
kubectl get namespaces
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-a -n testservice ping 10.47.255.249
kubectl get networkpolicy
kubectl get networkpolicy --all-namespace
kubectl get networkpolicy -n testservice
kubectl delete networkpolicy default-deny -n testservice
kubectl get networkpolicy --all-namespace
kubectl get networkpolicy -n testservice
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.250
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.251
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.249
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.248
kubectl exec -ti ubuntuiso -n juniper-iso2 ping 10.47.255.247
kubectl exec -ti ubuntuiso -n juniper-iso2 ping 10.47.255.250
ls
cd k8s_files/
ls
cat pod.yaml 
cat ubuntu-a.pod.yaml 
cat ubuntu-b.pod.yaml 
ls
cat ubuntu-green.pod.yaml 
cat ubuntu-red.pod.yaml 
cat ubuntu-blue.pod.yaml 
ls
cd namespaces_isolation/
ls
cat juniper-iso.yaml 
cat juniper-iso2.yaml 
cat juniper-iso3.yaml 
ls
cat ubuntu-yellow.pod.yaml 
cat ubuntu-iso.pod.yaml 
ls
cat juniper-iso.yaml 
cat ubuntu-yellow.pod.yaml 
contrailctl 
docker ps
docker ps | grep  zookeepe
docker exec -ti  analyticsdatabase_zookeeper_1 bash
docker ps 
docker exec -ti  control_control_1 bash
contrail-status
cd
ls
cd contrail-ansible-deployer/
ls
cd playbooks/
ls
cd ..
ls
cd playbooks/
ls
kubectl get cluster info
kubectl get ckubectl cluster-infoluster-info
kubectl cluster-info
ls
cd
ls
cd k8s_files/
ls
cd namespaces_isolation/
ls
cat juniper-iso3.yaml 
cd
ls
cd install_scripts/
ls
cd ..
ls
cd /mnt/
ls
cd
ls
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-a -n testservice
kubectl delete pods ubuntu-b -n testservice
kubectl delete pods ubuntu-a -n testservice2
kubectl delete pods ubuntu-b -n testservice2
kubectl get pods --all-namespaces -o wide
kubectl delete namespaces testservice
kubectl delete namespaces testservice2
kubectl get pods --all-namespaces -o wide
ls
cd k8s_files/
ls
cat ubuntu-green.pod.yaml 
cat ubuntu-red.pod.yaml 
kubectl get pods --all-namespaces -o wide
cd
ls
cd contrail-ansible-deployer/
ls
cd playbooks/
ls
cd ..
cd config/
ls'
ls
cat instances.yaml
cd /mnt/
ls
cat 02-patch-ansible-playbook 
cd
kubectl get pods --all-namespaces
kubectl get pods --all-namespaces -o wide
kubectl get pods namespaces
kubectl get namespaces
cd k8s_files/
ls
kuectl create -f ubuntu-b.pod.yaml -n juniper
kubectl create -f ubuntu-b.pod.yaml -n juniper
kubectl get pods --all-namespaces -o wide
kuebctl exec -ti ubuntu-a -n juniper 10.47.255.251
kubectl exec -ti ubuntu-a -n juniper 10.47.255.251
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.251
kubectl create namespace juniper2
kubectl create -f ubuntu-a.pod.yaml -n juniper2
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.250
ls
cat ubuntu-green.pod.yaml 
kubectl create -f ubuntu-green.pod.yaml -n juniper
kubectl get pods --all-namespaces -o wide
ls
cat ubuntu-red.pod.yaml 
kubectl create -f ubuntu-red.pod.yaml -n juniper
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-green -n juniper ping 192.168.2.3
cls
ls
cd namespaces_isolation/
ls
cat juniper-iso2.yaml 
ls
cat ubuntu-iso.pod.yaml 
kubectl exec -ti ubunuiso -n juniper-iso2 ping 10.47.255.250 
kubectl exec -ti ubuntuiso -n juniper-iso2 ping 10.47.255.250 
s
kubectl get pods --all-namespaces -o wide
docke
docker
cd k8s_files/
ls
cat ubuntu-a.pod.yaml 
ls
kubectl get pods --all-namespaces -o wide
kubectl exec -ti ubuntu-green  bash
kubectl exec -ti ubuntu-green -n juniper bash
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-green -n juniper
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-red -n juniper
cd /m
cd /mnt/
ls
ip addr
ls
cd /mnt/
ls
cat 06`
cat 06-disable-selinux 
ls
cat 06-disable-selinux 
exit
systemctl status firewalld.service
kubectl get nodes
cd /etc/
ls
cd
ls
cd /opt/cni/bin/
ls
cd
ls
cd k8s_files/
ls
cd ..
ls
cd contrail-ansible-deployer/
ls
cd config/
ls
car instances.yaml
cat instances.yaml
docker login hub.juniper.net
curl -u JNPR-FieldUser44 -X GET https://hub.juniper.net/v2/security/csrx/tags/list
ip a
kubectl get pods --all-namespaces -o wide
ls
mkdir cSRX
cd cSRX
ls
vi crsx.yaml
kubectl create secret docker-registry myregistrykey --docker-server=hub.juniper.net   --docker-username=JNPR-FieldUser44 --docker-password=ArUzN37C64PmXgKnusEW --docker-email=stella@juniper.net
ls
cd
ls
cd k8s_files/
ls
cat ubuntu-red.pod.yaml 
cd
ls
cd cSRX/
ls
kubectl create -f crsx.yaml 
kubectl get pods -o wide
kubectl describe pods csrx
kubectl get pods -o wide
kubectl describe pods crsx
kubectl get pods -o wide
kubectl describe pods crsx
kubectl get pods -o wide
kubectl describe pods crsx
kubectl get pods -o wide
ip a
kubectl delete pods crsx
kubectl get nodes
contrail-status
df -h
kubectl get pods --all-namespaces -o wide
kubectl edit pod kube-flannel
kubectl edit pod ubuntu-a -n juniper
kubectl get pods --all-namespaces -o wide
kubectl edit pod ubuntu-a -n juniper
kubectl get pods --all-namespaces -o wide
kubectl describe pod ubuntu-a -n juniper
kubectl get pods --all-namespaces -o wide
kubectl edit pod ubuntu-a -n juniper
kubectl get svc
kubectl edit pod ubuntu-a -n juniper
kubectl exec -ti ubuntu-a -n juniper ping 10.47.255.251
kubectl exec -ti ubuntu-a -n juniper ping ubuntu-b -n juniper
kubectl exec -ti ubuntu-a -n juniper ping ubuntu-b
service contrail-snmp-collector status
ping 192.168.221.187
exit
ping 172.27.224.11
ping 172.27.224.101
ping 172.27.224.11
ssh stella@172.27.224.11
exit
kubectl get nodes
ping 172.27.10.41
kubectl get nodes
ping 172.27.224.1
ping 172.27.10.163
kubectl get pods --all-namespaces -o wide
ping 172.27.10.53
kubectl get pods --all-namespace -o wide
kubectl get pods --all-namespaces -o wide
kubectl describe pods ubuntu-a -n juniper
ping 10.47.255.249
contrail-status
ls
kubectl get pods --all-namespace -o wide
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-a -n juniper2
kubectl delete pods ubuntuiso -n juniper-iso2
kubectl delete pods ubuntu-a -n juniper
kubectl delete pods ubuntu-b -n juniper
kubectl delete namespace juniper2
kubectl delete namespace juniper-iso
kubectl delete namespace juniper-iso2
kubectl get pods --all-namespaces -o wide
ks
ls
cd k8s_files/
ls
cat ubuntu-red.pod.yaml 
ls
mkdir chapter_7
cd chapter_7/
cp /root/k8s_files/ubuntu-red.pod.yaml .
ls
mv ubuntu-red.pod.yaml ubuntu-a.yaml
vi ubuntu-a.yaml 
kubectl create -f ubuntu-a.yaml 
kubectl get pods --all-namespaces -o wide
kubectl delete pods ubuntu-a
kubectl create -f ubuntu-a.yaml -n juniper
kubectl get pods --all-namespaces -o wide
kubectl get nodes
kubectl get pods --all-namespaces -o wide
kubectl get nodes
contrail-status
docker restart contrail-nodemgr
docker ps
docker restart analytics_nodemgr_1
contrail-status
docker ps
kubectl get pods --all-namespaces
kubectl get pods --all-namespaces -o wide
kubectl get nodes
kubectl get pods --all-namespaces -o wide
contrail-status
kubectl get pods --all-namespaces -o wide
contrail-status
