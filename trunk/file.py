import os.path
import gtk
from pcap import *


class File:

    def __init__(self,builder):
        
        self.filename = None
        self.builder = builder
        self.top_level = self.builder.get_object("top_level")        

    def load_file(self,dir):

        """
        chooser = gtk.FileChooserDialog("Open File...", self.top_level,
                                        gtk.FILE_CHOOSER_ACTION_OPEN,
                                        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                         gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        """
        self.chooser = self.builder.get_object("open_file_chooser_dialog")
        self.chooser.connect("selection-changed", self.file_chooser_selection_changed)

        chooser = self.chooser
        
        if os.path.exists(dir) == True:
            chooser.set_current_folder(dir)
        response = chooser.run()
        print response
        if response == 0:
            self.filename = chooser.get_filename()
            dir =  chooser.get_current_folder()
        chooser.destroy()

        if self.filename != None:
            try:
                fin = open(self.filename, 'rb')

                pcap = Reader(fin)
                pl_store = self.builder.get_object("pl_treestore")
                for ts, buf in pcap:
                    pl_store.append(None, (None,1,ts,"1.1.1.9","1.1.1.10","ftp","ftp-data"))
                fin.close
                return self.filename, dir

            except:
                # error loading file, show message to user
                #self.error_message ("Could not open file: %s" % filename)
                self.filename = None
                return self.filename, dir
        else:
            return None, None
    
    def file_chooser_selection_changed(self, item, data=None):
        print 'file chooser test'

