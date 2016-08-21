echo "Provisioning MSS..."
docker pull dsblox/mss
docker run -d -p 4000:4000 --name mss dsblox/mss
echo "...done!"
