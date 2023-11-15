import os

from google.appengine.api import app_identity
from google.appengine.api import modules


class EnvUtil(object):

    def gae_production_environment(self):

        if (
            os.getenv('SERVER_SOFTWARE') and
            os.getenv('SERVER_SOFTWARE').startswith('Google App Engine/')
        ):
            return True
        else:
            return False

    def gae_development_environment(self):
        return not self.gae_production_environment()

    def appengine_environment(self):

        return (
            os.getenv('SERVER_SOFTWARE') and
            (
                os.getenv('SERVER_SOFTWARE').startswith('Development') or
                self.gae_production_environment()
            )
        )

    def codeship(self):

        return os.getenv('CODESHIP') == 'TRUE'

    def app_id(self):
        return app_identity.get_application_id()

    def version_name(self):

        return modules.get_current_version_name()

    def module_name(self):

        return modules.get_current_module_name()

    def target(self):

        return self.version_name() + '.' + self.module_name()
