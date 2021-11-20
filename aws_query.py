import sys
import hmac
import base64
import hashlib
from urllib import parse

if len(sys.argv) != 6:
    print ('Output HTTPS GET links in JSON to be used to check the oracle status')
    print ('The default availability zone is ec2.us-east-1.amazonaws.com')
    print ('Usage: ami-id instance-id volume-id AWS-ID AWS-secret')
    print('Where:')
    print('ami-id is the AMI from which the instance was launched,')
    print('instance-id is the notary server instance, and')
    print('volume-id is the volume attached to it.')
    exit(0)

common_args = [('Expires=2030-01-01'), ('SignatureMethod=HmacSHA256'), ('SignatureVersion=2')]
availability_zone = 'ec2.us-east-1.amazonaws.com'
ami_id = sys.argv[1]
instance_id = sys.argv[2]
volume_id = sys.argv[3]
key = sys.argv[4]
secret = sys.argv[5]

def makeurl(args, endpoint, abbr):
    # sorting is essential, otherwise AWS will refuse the signature
    args.sort()
    argstr = ''
    for arg in args:
        argstr += parse.quote_plus(arg, '=')+'&'
    argstr = argstr[:-1]
    secret_bytes = bytes(secret , 'latin-1')
    mhmac = hmac.new(secret_bytes, ('GET\n'+endpoint+'\n/\n'+argstr).encode('utf-8'),hashlib.sha256)
    base64str = base64.b64encode(mhmac.digest()).strip().decode('utf-8')
    urlenc_sig = parse.quote_plus(base64str)
    final_string='https://'+endpoint+'/?'+argstr+'&Signature='+urlenc_sig
    print ('"' + final_string + '",', end = '')

print('The JSON below is an input for URLFetcher:')
print('[', end = '')
args = []
args.extend(common_args)
args.append('Action=DescribeInstances')
args.append('InstanceId='+instance_id)
args.append('AWSAccessKeyId='+key)
# Version= seems to be some AWS-specific expected value. If changed, it will
# cause the HTTP query to fail
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
makeurl(args, availability_zone, 'DIAud')

args = []
args.extend(common_args)
args.append('Action=DescribeInstanceAttribute')
args.append('InstanceId='+instance_id)
args.append('Attribute=kernel')
args.append('AWSAccessKeyId='+key)
args.append('Version=2014-10-01')
makeurl(args, availability_zone, 'DIAk')

args = []
args.extend(common_args)
args.append('Action=DescribeInstanceAttribute')
args.append('InstanceId='+instance_id)
args.append('Attribute=ramdisk')
args.append('AWSAccessKeyId='+key)
args.append('Version=2014-10-01')
makeurl(args, availability_zone, 'DIAr')

args = []
args.extend(common_args)
args.append('Action=DescribeImages')
args.append('ImageId.1='+ami_id)
args.append('AWSAccessKeyId='+key)
args.append('Version=2014-10-01')
makeurl(args, availability_zone, 'DImg')
print(']')