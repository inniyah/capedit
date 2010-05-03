#!/usr/bin/env python

import sys
try:
     import pygtk
     pygtk.require("2.0")
except:
      pass
try:
    import gtk
    import gtk.glade
except:
    sys.exit(1)
    
import sys
import os
import gtk
from pcap import Reader


class GuiInit:
    
    # When our window is destroyed, we want to break out of the GTK main loop. 
    # We do this by calling gtk_main_quit(). We could have also just specified 
    # gtk_main_quit as the handler in Glade!
    def on_top_level_destroy(self, widget, data=None):
        gtk.main_quit()
        
    # Called when the user clicks the 'Open' menu. We need to prompt for save if 
    # thefile has been modified, allow the user to choose a file to open, and 
    # then call load_file() on that file.    
    def on_open_menu_item_activate(self, menuitem, data=None):
        
        #if self.check_for_save(): self.on_save_menu_item_activate(None, None)
        filename = self.get_open_filename()
        if filename: self.load_file(filename)
        
    # We call get_open_filename() when we want to get a filename to open from the
    # user. It will present the user with a file chooser dialog and return the 
    # filename or None.    
    def get_open_filename(self):
        
        filename = None
        chooser = gtk.FileChooserDialog("Open File...", self.window,
                                        gtk.FILE_CHOOSER_ACTION_OPEN,
                                        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, 
                                         gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        
        response = chooser.run()
        if response == gtk.RESPONSE_OK: 
            filename = chooser.get_filename()
        chooser.destroy()
        
        return filename
    
    # We call load_file() when we have a filename and want to load it into the 
    # buffer for the GtkTextView. The previous contents are overwritten.    
    def load_file(self, filename):
    
        # add Loading message to status bar and ensure GUI is current
        #self.statusbar.push(self.statusbar_cid, "Loading %s" % filename)
        while gtk.events_pending(): gtk.main_iteration()
        
        try:
            # get the file contents
            fin = open(filename, "rb")
            text = fin.read()
            #fin.close()
            
            
            pcap = Reader(fin)
            print pcap
            for ts, buf in pcap:
                print ts
            fin.close
            # disable the text view while loading the buffer with the text
            #self.text_view.set_sensitive(False)
            #buff = self.text_view.get_buffer()
            #buff.set_text(text)
            #buff.set_modified(False)
            #self.text_view.set_sensitive(True)
            
            # now we can set the current filename since loading was a success
            self.filename = filename
            
        except:
            # error loading file, show message to user
            #self.error_message ("Could not open file: %s" % filename)
            
        # clear loading status and restore default 
        #self.statusbar.pop(self.statusbar_cid)
        #self.reset_default_status()
            pass

    def __init__(self):
    
        # Default values
        self.filename = None
        self.about_dialog = None
        
        # use GtkBuilder to build our interface from the XML file 
        try:
            builder = gtk.Builder()
            builder.add_from_file("gui.glade") 
        except:
            #self.error_message("Failed to load UI XML file: tutorial.xml")
            sys.exit(1)
            
        # get the widgets which will be referenced in callbacks
        self.window = builder.get_object("top_level")
        #self.statusbar = builder.get_object("statusbar")
        #self.text_view = builder.get_object("text_view")
        
        # connect signals
        builder.connect_signals(self)
        
        # set the text view font
        #self.text_view.modify_font(pango.FontDescription("monospace 10"))
        
        # set the default icon to the GTK "edit" icon
        #gtk.window_set_default_icon_name(gtk.STOCK_EDIT)
        
        # setup and initialize our statusbar
        #self.statusbar_cid = self.statusbar.get_context_id("Tutorial GTK+ Text Editor")
        #self.reset_default_status()

    # Run main application window
    def main(self):
        self.window.show()
        gtk.main()
    
if __name__ == "__main__":
    capedit = GuiInit()
    capedit.main()