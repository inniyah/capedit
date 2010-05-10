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
from pcap import *

class Menu:
	
    def __init__(self, builder, top_level):
	self.top_level = top_level
	self.builder = builder
	open_menu_item = self.builder.get_object("open_menu_item")
	open_menu_item.connect("activate", self.on_open_menu_item_activate)

	view_main_toolbar_item = self.builder.get_object("view_main_toolbar_item")
	view_main_toolbar_item.connect("toggled", self.view_main_toolbar_item_toggled_cb)

        view_send_toolbox_item = self.builder.get_object("view_send_toolbox_item")
        view_send_toolbox_item.connect("toggled", self.view_send_toolbox_item_toggled_cb)

        view_packet_list_display_item = self.builder.get_object("view_packet_list_display_item")
        view_packet_list_display_item.connect("toggled", self.view_packet_list_display_item_toggled_cb)

        view_packet_display_item = self.builder.get_object("view_packet_display_item")
        view_packet_display_item.connect("toggled", self.view_packet_display_item_toggled_cb)

        view_packet_byte_display_item = self.builder.get_object("view_packet_byte_display_item")
        view_packet_byte_display_item.connect("toggled", self.view_packet_byte_display_item_toggled_cb)

        view_statusbar_item = self.builder.get_object("view_statusbar_item")
        view_statusbar_item.connect("toggled", self.view_statusbar_item_toggled_cb)

    def on_open_menu_item_activate(self, menuitem, data=None):

        filename = self.get_open_filename()
        if filename: self.load_file(filename)

    def view_main_toolbar_item_toggled_cb(self, menuitem, data=None):
	main_toolbar = self.builder.get_object("main_toolbar")
	switch =("OFF", "ON")[menuitem.get_active()]
	if switch == "OFF":
	    main_toolbar.hide()
	elif switch == "ON":
	    main_toolbar.show()	

    def view_send_toolbox_item_toggled_cb(self, menuitem, data=None):
        send_toolbox = self.builder.get_object("send_toolbox")
	switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            send_toolbox.hide()
        elif switch == "ON":
            send_toolbox.show()

    def view_packet_list_display_item_toggled_cb(self, menuitem, data=None):
        packet_list_display = self.builder.get_object("packet_list_display_vbox")
	switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            packet_list_display.hide()
        elif switch == "ON":
            packet_list_display.show()

    def view_packet_display_item_toggled_cb(self, menuitem, data=None):
        packet_display = self.builder.get_object("packet_display_vbox")
	switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            packet_display.hide()
        elif switch == "ON":
            packet_display.show()

    def view_packet_byte_display_item_toggled_cb(self, menuitem, data=None):
        packet_byte_display = self.builder.get_object("packet_byte_display_vbox")
	switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            packet_byte_display.hide()
        elif switch == "ON":
            packet_byte_display.show()

    def view_statusbar_item_toggled_cb(self, menuitem, data=None):
        statusbar = self.builder.get_object("statusbar")
        switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            statusbar.hide()
        elif switch == "ON":
            statusbar.show()

    def get_open_filename(self):

        filename = None
        chooser = gtk.FileChooserDialog("Open File...", self.top_level,
                                        gtk.FILE_CHOOSER_ACTION_OPEN,
                                        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                         gtk.STOCK_OPEN, gtk.RESPONSE_OK))

        response = chooser.run()
        if response == gtk.RESPONSE_OK:
            filename = chooser.get_filename()
        chooser.destroy()

        return filename

    def load_file(self, filename):

        while gtk.events_pending(): gtk.main_iteration()

        try:

            # get the file contents
            fin = open(filename, 'rb')

            pcap = Reader(fin)
            for ts, buf in pcap:
                input('press the key')
                print ts
            fin.close
            self.filename = filename

        except:
            # error loading file, show message to user
            #self.error_message ("Could not open file: %s" % filename)
            pass


class GuiInit:
    
    def on_top_level_destroy (self, widget, data=None):

	gtk.main_quit()

    def on_checkbutton1_toggled(self, widget, data=None):

        tog_button = self.builder.get_object("checkbutton1")
        switch =("OFF", "ON")[tog_button.get_active()]
        if switch == 'OFF':
            tog_button.set_active(1)
        if switch == 'ON':
            tog_button.set_active(0)

    
    def __init__(self):
    
        # Default values
        self.filename = None
        
        # use GtkBuilder to build our interface from the XML file 
        try:
            self.builder = gtk.Builder()
            self.builder.add_from_file("main.glade") 
        except:
            #self.error_message("Failed to load UI XML file: tutorial.xml")
            sys.exit(1)
            
        # get the widgets which will be referenced in callbacks
        self.top_level = self.builder.get_object("top_level")
        
        # Create an accelerator group
        accelgroup = self.builder.get_object("accelgroup1")

        # Add the accelerator group to the toplevel window
        self.top_level.add_accel_group(accelgroup)

	self.top_level.connect("destroy", self.on_top_level_destroy)

	Menu(self.builder, self.top_level)

    # Run main application window
    def main(self):
        self.top_level.show()
        gtk.main()
    
if __name__ == "__main__":
    capedit = GuiInit()
    capedit.main()
