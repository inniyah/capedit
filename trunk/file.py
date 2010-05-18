import gtk
from pcap import *

class File:

    def __init__(self,builder):
        
        self.filename = None
        self.builder = builder
        self.top_level = self.builder.get_object("top_level")        

    def get_open_filename(self):

        chooser = gtk.FileChooserDialog("Open File...", self.top_level,
                                        gtk.FILE_CHOOSER_ACTION_OPEN,
                                        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                         gtk.STOCK_OPEN, gtk.RESPONSE_OK))

        response = chooser.run()
        if response == gtk.RESPONSE_OK:
            filename = chooser.get_filename()
        chooser.destroy()

        return filename

    def load_file(self):

        filename = self.get_open_filename()
        try:

            fin = open(filename, 'rb')

            pcap = Reader(fin)
            pl_store = self.builder.get_object("pl_treestore")
            for ts, buf in pcap:
                print ts
                pl_store.append(None, (None,1,ts,"1.1.1.9","1.1.1.10","ftp","ftp-data"))
            fin.close
            self.filename = filename

        except:
            # error loading file, show message to user
            #self.error_message ("Could not open file: %s" % filename)
            pass

