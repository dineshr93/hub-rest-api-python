#not needed if already installed in the machine
#python3 -m pip install blackduck 

echo PROJECT_NAME=$PROJECT_NAME >.env
echo PROJECT_VERSION=$PROJECT_VERSION >>.env
echo BLACKDUCK_URL=$BLACKDUCK_URL >>.env
echo BLACKDUCK_TOKEN=$BLACKDUCK_TOKEN >>.env

echo {\"baseurl\": \"$BLACKDUCK_URL\",\"api_token\": \"$BLACKDUCK_TOKEN\",\"insecure\": true,\"debug\": false} > .restconfig.json


echo "========================Result Section====================================="
OUTPUT=$(bash examples/bomdiff2.sh -u $BLACKDUCK_URL -a $BLACKDUCK_TOKEN -p $PROJECT_NAME)
totalAddedComponents=$(echo $OUTPUT | grep -P '(totalAddedComponents) \d+' -o)
totalRemovedComponents=$(echo $OUTPUT | grep -P '(totalRemovedComponents) \d+' -o)

echo "${OUTPUT}" | mail -s "bomdiffAsterix : $totalAddedComponents: $totalRemovedComponents" dineshr93@gmail.com Dinesh.Ravi@elektrobit.com
