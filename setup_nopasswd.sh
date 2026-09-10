echo 'adty17 ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/adty17 > /dev/null
sudo chmod 440 /etc/sudoers.d/adty17
echo "Passwordless sudo configured for adty17"
