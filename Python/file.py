import os.path
import gtk

import pcap
import ethernet
import binascii


class File:

    def __init__(self,builder):
        
        self.filename = None
        self.builder = builder
        self.top_level = self.builder.get_object("top_level")        

    def load_file(self,dir):
            
        chooser = gtk.FileChooserDialog("Open File...", self.top_level,
                                        gtk.FILE_CHOOSER_ACTION_OPEN,
                                        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                         gtk.STOCK_OPEN, gtk.RESPONSE_OK))
    
        #self.chooser = self.builder.get_object("open_file_chooser_dialog")
        #self.chooser.connect("selection-changed", self.file_chooser_selection_changed)

        #chooser = self.chooser
        
        if os.path.exists(dir) == True:
            chooser.set_current_folder(dir)
        response = chooser.run()
        self.filename = chooser.get_filename()
        dir =  chooser.get_current_folder()
        chooser.destroy()

        if self.filename != None:
            try:
                fin = open(self.filename, 'rb')
                print 'test'
                pcap1 = pcap.Reader(fin)
                print 'test0'
                pl_store = self.builder.get_object("pl_treestore")
                print 'test1'
                for ts, buf in pcap1:
                    print 'test2'
                    eth = ethernet.Ethernet(buf)
                    print 'test3'
                    src = binascii.hexlify(eth.src)
                    blocks = [src[x:x+2] for x in xrange(0, len(src), 2)]
                    src_mac = ':'.join(blocks)
                    print eth.src_name
                    dst = binascii.hexlify(eth.src)
                    blocks = [dst[x:x+2] for x in xrange(0, len(dst), 2)]
                    dst_mac = ':'.join(blocks)
                    name = getattr(eth,eth.dst+'_name')
                    print name
                    pl_store.append(None, (None,1,ts,src_mac,dst_mac,"ethernet","ethernet packet"))
                fin.close
                return self.filename, dir

            except Exception, e:
                print e
                # error loading file, show message to user
                #self.error_message ("Could not open file: %s" % filename)
                self.filename = None
                return self.filename, dir
        else:
            return None, None
    
    def file_chooser_selection_changed(self, item, data=None):
        pass

