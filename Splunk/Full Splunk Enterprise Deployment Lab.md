 $${{\color{Lime}\huge{\textsf{Splunk Enterprise Lab\ }}}}\$$


$${{\color{Blue}\huge{\textsf{Overview }}}}\$$

---
In this lab I set up a splunk enviroment consisiting of:
| VM                   | OS              | Role(s)                                                                                                        |
| -------------------- | ----------------|--------------------------------------------------------------------------------------------------------------- |
| Virtual Machine 1    | RHEL 10         | **Universal Forwarder (UF)**                                                                                   |
| Virtual Machine 2    | RHEL 10         | **Search Head (SH)**                                                                                           |
| Virtual Machine 3    | RHEL 10         | **Deployment Server**+ ** Monitoring Console**+ **License Manager**                                            |
| Virtual Machine 4    | RHEL 10         | **Cluster Manager**                                                                                            |
| Virtual Machine 5    | RHEL 10         | **Indexer**                                                                                                    |
| Virtual Machine 6    | RHEL 10         | **Indexer**                                                                                                    |
| Virtual Machine 7    | RHEL 10         | **Indexer**                                                                                                    |;



$${{\color{Yellow}\huge{\textsf{Architecture }}}}\$$
<div align="center">
 <img src="https://github.com/CyberFlash-1/Flash028/blob/e0f02ee44af691681fe8ddac7590adc28a12b1fb/IMAGES/Enterprise%20Dployment.png">
</div>
  </br>
  
<div align="center">
  

${{\color{Yellow}\large{\textsf{Step 1: Download Splunk\ }}}}\$
```
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-Linux-x86_64.tgz'
tar -xvzf splunk.tgz -C /opt
```
Create the splunk User from the ROOT User Account 
```
sudo su
useradd splunk
sudo chown -R splunk:splunk /opt/splunk    #### This give the splunk user ownership/permissions for the splunk directory #####
sudo su - splunk
cd /opt/splunk/bin
/opt/splunk/bin/splunk start --accept-license
./splunk stop
```


${{\color{Yellow}\large{\textsf{Step 2:Enable boot-start\ }}}}\$

```
cd /opt/splunk/bin
./splunk enable boot-start -systemd-managed 1 -create-polkit-rules 1 -user splunk
#### revert back to the splunk user and start splunk ####
sudo su - splunk
cd /opt/splunk/bin
./splunk start
```
${{\color{Yellow}\large{\textsf{Step 2: Enabling Clustering \ }}}}\$
</div>
