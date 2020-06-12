package bless

import (
	"github.com/Benbentwo/blessclient/pkg/config"
	"github.com/Benbentwo/blessclient/pkg/util"
	"github.com/Benbentwo/utils/log"
	util2 "github.com/Benbentwo/utils/util"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"os"
	"time"
)

func Bless(region string, nocache bool, showgui bool, hostname string, blessConfig config.Config, idfile string) error {
	log.Logger().Debugf("Starting...")

	if os.Getenv("MFA_ROLE") != "" {
		_ = util.UnsetEnvTokens()
	}

	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	blesscachefile := &BlessCacheFile{
		Enabled:  !nocache,
		filepath: "",
		filename: "",
	}
	err := blesscachefile.LoadCache()
	if err != nil {
		return err
	}

	username, _ := GetUsername(svc, &blessConfig.ConfigClient.Cache)
	cert_file := idfile + "-cert.pub"
	log.Logger().Debugf("Using identity file: %s", idfile)
	blessLambdaConfig := blessConfig.ConfigBless
	roleCreds := ""
	kmsauthConfig := blessConfig.ConfigKmsAuth

	fixedIp := false
	if os.Getenv("BLESSFIXEDIP") == "" {
		fixedIp = true
	}
	userIP := UserIP{
		CacheFile:    *blesscachefile,
		MaxCacheTime: time.Duration.Seconds() * blessLambdaConfig.IpCacheLifetime,
		IpUrls:       blessConfig.ConfigClient.IpUrls,
		FixedIp:      fixedIp,
	}

	if !nocache {

	}

	return nil
}

//    # Check if we can skip asking for MFA code
//    if nocache is not True:
//        if check_fresh_cert(cert_file, bless_lambda_config, bless_cache, userIP):
//            logging.debug("Already have fresh cert")
//            sys.exit(0)
//
//        if ('AWS_SECURITY_TOKEN' in os.environ):
//            try:
//                # Try doing this with our env's creds
//                kmsauth_token = get_kmsauth_token(
//                    None,
//                    kmsauth_config,
//                    username,
//                    cache=bless_cache
//                )
//                logging.debug(
//                    "Got kmsauth token by default creds: {}".format(kmsauth_token))
//                role_creds = get_blessrole_credentials(
//                    aws.iam_client(), None, bless_config, bless_cache)
//                logging.debug("Default creds used to assume role use-bless")
//            except:
//                pass  # TODO
//
//        if role_creds is None:
//            try:
//                # Try using creds stored by mfa.sh
//                creds = load_cached_creds(bless_config)
//                if creds:
//                    kmsauth_token = get_kmsauth_token(
//                        creds,
//                        kmsauth_config,
//                        username,
//                        cache=bless_cache
//                    )
//                    logging.debug(
//                        "Got kmsauth token by cached creds: {}".format(kmsauth_token))
//                    role_creds = get_blessrole_credentials(
//                        aws.iam_client(), creds, bless_config, bless_cache)
//                    logging.debug("Assumed role use-bless using cached creds")
//            except:
//                pass
//
//    if role_creds is None:
//        mfa_pin = get_mfa_token(showgui, hostname)
//        if mfa_pin is None:
//            sys.stderr.write("Certificate creation canceled\n")
//            sys.exit(1)
//        mfa_arn = awsmfautils.get_serial(aws.iam_client(), username)
//        try:
//            creds = aws.sts_client().get_session_token(
//                DurationSeconds=bless_config.get_client_config()['user_session_length'],
//                SerialNumber=mfa_arn,
//                TokenCode=mfa_pin
//            )['Credentials']
//        except (ClientError, ParamValidationError):
//            sys.stderr.write("Incorrect MFA, no certificate issued\n")
//            sys.exit(1)
//
//        if creds:
//            save_cached_creds(creds, bless_config)
//        kmsauth_token = get_kmsauth_token(
//            creds,
//            kmsauth_config,
//            username,
//            cache=bless_cache
//        )
//        logging.debug("Got kmsauth token: {}".format(kmsauth_token))
//        role_creds = get_blessrole_credentials(
//            aws.iam_client(), creds, bless_config, bless_cache)
//
//    bless_lambda = BlessLambda(bless_lambda_config, role_creds, kmsauth_token, region)
//
//    # Do bless
//    if show_feedback:
//        sys.stderr.write(
//            "Requesting certificate for your public key"
//            + " (set BLESSQUIET=1 to suppress these messages)\n"
//        )
//    public_key_file = identity_file + '.pub'
//    with open(public_key_file, 'r') as f:
//        public_key = f.read()
//
//    if public_key[:8] != 'ssh-rsa ':
//        raise Exception(
//            'Refusing to bless {}. Probably not an identity file.'.format(identity_file))
//
//    my_ip = userIP.getIP()
//    ip_list = "{},{}".format(my_ip, bless_config.get_aws_config()['bastion_ips'])
//    payload = {
//        'bastion_user': username,
//        'bastion_user_ip': my_ip,
//        'remote_usernames': username,
//        'bastion_ips': ip_list,
//        'command': '*',
//        'public_key_to_sign': public_key,
//    }
//    cert = bless_lambda.getCert(payload)
//
//    logging.debug("Got back cert: {}".format(cert))
//
//    if cert[:29] != 'ssh-rsa-cert-v01@openssh.com ':
//        error_msg = json.loads(cert)
//        if 'errorType' in error_msg and error_msg['errorType'] == 'KMSAuthValidationError' and nocache is False:
//            logging.debug("KMSAuth error with cached token, purging cache.")
//            clear_kmsauth_token_cache(kmsauth_config, bless_cache)
//            raise LambdaInvocationException('KMSAuth validation error')
//
//        if 'errorType' in error_msg and error_msg['errorType'] == 'ClientError':
//            raise LambdaInvocationException(
//                'The BLESS lambda experienced a client error. Consider trying in a different region.'
//            )
//
//        if ('errorType' in error_msg and error_msg['errorType'] == 'InputValidationError'):
//            raise Exception(
//                'The input to the BLESS lambda is invalid. Please update your blessclient by running `make update` in'
//                ' the bless folder.')
//
//        raise LambdaInvocationException(
//            'BLESS client did not recieve a valid cert. Instead got: {}'.format(cert))
//
//    ssh_agent_remove_bless(identity_file)
//    with open(cert_file, 'w') as cert_file:
//        cert_file.write(cert)
//    ssh_agent_add_bless(identity_file)
//
//    bless_cache.set('certip', my_ip)
//    bless_cache.save()
//
//    logging.debug("Successfully issued cert!")
//    if show_feedback:
//        sys.stderr.write("Finished getting certificate.\n")
// func GetBlessCache()
// def get_bless_cache(nocache, bless_config):
// client_config = bless_config.get_client_config()
// cachedir = os.path.join(
// os.getenv('HOME', os.getcwd()),
// client_config['cache_dir'])
// cachemode = BlessCacheFile.CACHEMODE_RECACHE if nocache else BlessCacheFile.CACHEMODE_ENABLED
// return BlessCacheFile(cachedir, client_config['cache_file'], cachemode)
//

func GetUsername(svc *iam.IAM, cache *BlessCacheFile) (string, error) {
	un := cache.Cache.Username
	if un != "" {
		return un, nil
	}

	user, err := svc.GetUser(nil)
	if err != nil {
		_ = util.UnsetEnvTokens()
		user, err = svc.GetUser(nil)
		if err != nil {
			log.Logger().Errorf("Can't get your user information from AWS! Either you don't have your user aws credentials set as [default] in ~/.aws/credentials, or you have another process setting AWS credentials for a service account in your environment.")
			return "", err
		}

	}

	username := user.User.UserName
	cache.Cache.Username = *username
	cache.Cache.Userarn = *user.User.Arn
	err = cache.SaveCache("")
	return *username, err

}

func CheckFreshCert(certFile string, configFile config.Config, cache BlessCache, ip UserIP) bool {
	exists, err := util2.FileExists(certFile)
	if err != nil {
		log.Logger().Warnf("checking for fresh cert failed %s does not exist, %s", certFile, err)
		return false
	}
	if !exists {
		return false
	}
	certStats, _ := os.Stat(certFile)
	certLife := time.Now().Sub(certStats.ModTime())
	if certLife.Seconds() < float64(configFile.ConfigBless.CertLifetime-15) {
		if certLife.Seconds() < float64(configFile.ConfigBless.IpCacheLifetime) || configFile.ConfigClient.Cache.Cache.CertIp == ip.GetIp() {
			return true
		}
	}
	return false
}
