echo "MSS: Provisioning MSS..."
echo "MSS: Pulling dsblox/mss image from Docker Hub..."
docker pull dsblox/mss
echo "MSS: Running dsblox/mss image as server daemon..."
docker run -d -p 4000:4000 --name mss dsblox/mss
echo "MSS: Message Secure Send Server running on port 4000." 
