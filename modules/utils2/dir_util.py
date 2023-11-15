import os


class DirUtil(object):

    def __init__(self, dir_name):
        self.dir_name = dir_name

        if not self.dir_name.endswith('/'):
            self.dir_name += '/'

    def dirs(self):

        dirs = next(os.walk(self.dir_name))[1]

        dirs_full_path = [self.dir_name + dir_name for dir_name in dirs]

        return dirs_full_path

    def files(self):

        files = next(os.walk(self.dir_name))[2]

        files_full_path = [self.dir_name + file_name for file_name in files]

        return files_full_path

