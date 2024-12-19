# Tested on Ubuntu 64-bit 22.04 LTS


sudo chown -R $USER /opt

sudo apt-get install git-core python3-pip -y

# Setup git-lfs and clean_up_ghidra_project_dir
sudo apt-get install git-lfs
git lfs install

# Install Ghidra 10.1.4
wget -O /opt/ghidra_10.1.4_PUBLIC_20220519.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.4_build/ghidra_10.1.4_PUBLIC_20220519.zip

cd /opt
unzip /opt/ghidra_10.1.4_PUBLIC_20220519.zip

# Install jdk needed for Ghidra
sudo apt-get install openjdk-11-jdk -y

# Install eclipse to /opt (https://stackoverflow.com/questions/35282460/install-eclipse-via-terminal)
cd /opt
wget http://www.mirrorservice.org/sites/download.eclipse.org/eclipseMirror/technology/epp/downloads/release/2022-06/R/eclipse-committers-2022-06-R-linux-gtk-x86_64.tar.gz

cd /opt
sudo tar -xvf eclipse-committers-2022-06-R-linux-gtk-x86_64.tar.gz
sudo chown -R $USER eclipse

#Note: The eclipse location for Ghidra is the following: /opt/eclipse

# Needed for building module extension
wget https://services.gradle.org/distributions/gradle-6.8-bin.zip -P /tmp
sudo unzip -d /opt/gradle /tmp/gradle-*.zip


# Parsing pefiles
pip3 install pefile
pip3 install numpy==1.23.1

pip3 install pyvex==9.2.8


#Install protoc compiler
sudo apt-get install protobuf-compiler -y


