import sys
import hmac
import base64
import hashlib
import urllib 

if len(sys.argv) != 5:
    print ('Output HTTPS GET links to be used to check the oracle status')
    print ('The default availability zone is ec2.us-east-1.amazonaws.com')
    print ('Usage: instance-id volume-id AWS-ID AWS-secret')
    print ('Where instance-id is the oracle instance and volume-id is the volume attached to it')
    exit(0)

common_args = [('Expires=2019-01-01'), ('SignatureMethod=HmacSHA256'), ('SignatureVersion=2')]
availability_zone = 'ec2.us-east-1.amazonaws.com'
instance_id = sys.argv[1]
volume_id = sys.argv[2]
key = sys.argv[3]
secret = sys.argv[4]

def makeurl(args, endpoint, abbr):
    args.sort()
    argstr = ''
    for arg in args:
        argstr += urllib.quote_plus(arg, '=')+'&'
    argstr = argstr[:-1]
    mhmac = hmac.new(secret, ('GET\n'+endpoint+'\n/\n'+argstr).encode('utf-8'),hashlib.sha256)
    base64str = base64.b64encode(mhmac.digest()).strip().decode('utf-8')
    urlenc_sig = urllib.quote_plus(base64str)
    final_string='https://'+endpoint+'/?'+argstr+'&Signature='+urlenc_sig
    print ("'" + abbr + "':'" + final_string + "',")


args = []
args.extend(common_args)
args.append('Action=DescribeInstances')
args.append('InstanceId='+instance_id)
args.append('AWSAccessKeyId='+key)
args.append('Version=2014-10-01')
makeurl(args, availability_zone, 'DI')

args = []
args.extend(common_args)
args.append('Action=DescribeVolumes')
args.append('VolumeId='+volume_id)
args.append('AWSAccessKeyId='+key)
args.append('Version=2014-10-01')
makeurl(args, availability_zone, 'DV')

args = []
args.extend(common_args)
args.append('Action=GetConsoleOutput')
args.append('InstanceId='+instance_id)
args.append('AWSAccessKeyId='+key)
args.append('Version=2014-10-01')
makeurl(args, availability_zone, 'GCO')

args = []
args.extend(common_args)
args.append('Action=GetUser')
args.append('AWSAccessKeyId='+key)
args.append('Version=2010-05-08')
makeurl(args, 'iam.amazonaws.com', 'GU')

args = []
args.extend(common_args)
args.append('Action=DescribeInstanceAttribute')
args.append('InstanceId='+instance_id)
args.append('Attribute=userData')
args.append('AWSAccessKeyId='+key)
args.append('Version=2014-10-01')
makeurl(args, availability_zone, 'DIA')
