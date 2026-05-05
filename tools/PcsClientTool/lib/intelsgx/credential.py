try:
    import keyring
except:
    keyring = None
import getpass

class Credentials:
    APPNAME = 'PcsClient'
    KEY_PCS_APIKEY = 'PCS_API_KEY'

    def get_pcs_api_key(self):
        pcs_api_key = ""
        if keyring is not None:
            try:
                print("Please note: A prompt may appear asking for your keyring password to access stored credentials.")
                pcs_api_key = keyring.get_password(self.APPNAME, self.KEY_PCS_APIKEY)
            except keyring.errors.KeyringError as ke:
                pcs_api_key = ""
        
        while pcs_api_key is None or pcs_api_key == '':
            pcs_api_key = getpass.getpass(prompt="Please input ApiKey for Intel PCS:")
            # prompt saving password
            if pcs_api_key != "":
                save_passwd = input("Would you like to remember Intel PCS ApiKey in OS keyring? (y/n)")
                if save_passwd.lower() == 'y':
                    self.set_pcs_api_key(pcs_api_key)

        return pcs_api_key

    def set_pcs_api_key(self, apikey):
        if keyring is not None:
            try:
                print("Please note: A prompt may appear asking for your keyring password to access stored credentials.")
                keyring.set_password(self.APPNAME, self.KEY_PCS_APIKEY, apikey)
            except keyring.errors.PasswordSetError as ke:
                print("Failed to store PCS API key.")
                return False
        return True
