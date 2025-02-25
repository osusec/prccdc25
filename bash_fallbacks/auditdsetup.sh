#!/bin/bash

declare -A osInfo;
osInfo[/etc/redhat-release]=yum
osInfo[/etc/arch-release]=pacman
osInfo[/etc/gentoo-release]=emerge
osInfo[/etc/SuSE-release]=zypp
osInfo[/etc/debian_version]=apt-get
osInfo[/etc/alpine-release]=apk

# Identify package manager
pkg_manager=""
for f in "${!osInfo[@]}"
do
    if [[ -f $f ]]; then
        pkg_manager=${osInfo[$f]}
        echo "Detected package manager: $pkg_manager"
        break
    fi
done

# Function to install a package
install_package() {
    local package=$1

    if [[ -z "$pkg_manager" ]]; then
        echo "Error: Could not determine package manager."
        exit 1
    fi

    case $pkg_manager in
        yum)
            sudo yum install -y "$package"
            ;;
        apt-get)
            sudo apt-get update && sudo apt-get install -y "$package"
            ;;
        pacman)
            sudo pacman -Sy --noconfirm "$package"
            ;;
        emerge)
            sudo emerge "$package"
            ;;
        zypper)
            sudo zypper install -y "$package"
            ;;
        apk)
            sudo apk add "$package"
            ;;
        *)
            echo "Error: Unsupported package manager: $pkg_manager"
            exit 1
            ;;
    esac
}

if [[ $pkg_manager == "yum" ]]; then
    install_package "audit"
else
    install_package "auditd"
fi

mkdir -p /etc/audit/rules.d/
cp /etc/audit/rules.d/audit.rules /etc/audit/old.rules
wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -O /etc/audit/rules.d/audit.rules
augenrules –-load

auditctl -a exit,always -F arch=b64 -F euid=0 -S execve
auditctl -a exit,always -F arch=b32 -F euid=0 -S execve
# start and enable
systemctl start auditd
systemctl enable auditd

echo "auditing setup successful"
echo "I see everything..."
