/* main.c
 *
 * $Id: main.c 1 2010-04-11 21:04:36 vijay mohan $
 *
 * PacketSquare-capedit - Pcap Edit & Replay Tool
 * By vijay mohan <vijaymohan@packetsquare.com>
 * Copyright 2010 vijay mohan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <gtk/gtk.h>
#include "main.h"
#include "pcap.h"
#include "packet.h"
#include <string.h>
#include "str_to.h"
#include <unistd.h>
#include "error.h"
#include "tags.h"
#include <arpa/inet.h>

GtkWidget *top_level;
static GtkWidget *mn_vbox;
static GtkWidget *vpaned1, *vpaned2, *vpaned3;
static GtkWidget *pl_scrolled_win;
static GtkWidget *pl_treeview;
static GtkWidget *p_scrolled_win;
static GtkWidget *p_treeview;
static GtkWidget *intf_combo;
static GtkWidget *send_all_check;
static GtkTreeStore *pl_store;
static GtkTreeStore *p_store;
static GtkTreeIter pl_iter,p_iter,p_child, p_child1;
static GtkWidget *hex_scrolled_win;
static GtkWidget *hex_textview;
static GtkTextBuffer *hex_buffer;
struct pak_file_info *po_info = NULL;
static char f_name[255];
pcap_t *p = NULL;
struct pak_file_info *fpak_curr_info = NULL;
char ptype[50];
int record_l1;
int record_l2;
uint16_t p_ref_proto;
static unsigned long tsec = 0;
static unsigned long tusec = 0;

static uint8_t opt = 45;

void
display_p_tree_data(uint8_t *pak);

void
pak_list_init(void)
{

	po_info = (struct pak_file_info *)malloc(sizeof(struct pak_file_info));
	po_info->pak_no    = 0;
	po_info->offset    = 0;
	po_info->pak       = NULL;
	po_info->mem_alloc = 0;
	po_info->prev      = NULL;
	po_info->next      = NULL;
}

void 
pak_list_free(void)
{
        struct pak_file_info *temp_next, *temp;

        if (po_info != NULL) {
                temp_next = po_info->next;
                while(temp_next != NULL) {
			if (temp_next->mem_alloc == 1) {
                        	free(temp_next->pak);
			}
                        temp = temp_next;
                        temp_next = temp->next;
                        free(temp);

                }
		po_info->prev = NULL;
                po_info->next = NULL;
        }
}

struct pak_file_info *
pak_list_add(struct pak_file_info **current, uint32_t offset, uint32_t pak_no)
{
	struct pak_file_info *temp;

	temp = (struct pak_file_info *)malloc(sizeof(struct pak_file_info));
	temp->pak_no = pak_no;
	temp->offset = offset;
	memcpy((void *)&(temp->pak_hdr), (void *)&(p->pak_hdr), sizeof(struct pcap_pkthdr));
	temp->pak = NULL;
	temp->pak_len = p->cap_len;
	temp->mem_alloc = 0;
	temp->prev = *current;
	temp->next = NULL;

	(*current)->next = temp;
	
	return temp;

}

struct pak_file_info *
pak_list_get(uint32_t no)
{
	struct pak_file_info *temp = po_info;

	while(temp->pak_no != no) {
		temp = temp->next;
		if (temp == NULL) {
			return NULL;
		}
	}
	return temp;
}

uint8_t
pak_list_del_node(uint32_t no)
{
	struct pak_file_info *cur = po_info;
	struct pak_file_info *cur_temp = NULL;
	uint32_t pak_count = no-1;

	while(cur->pak_no != no) {
		cur = cur->next;
		if (cur == NULL) {
			return (0);
		}
	}

	cur_temp = cur->prev;
	cur->prev->next = cur->next;
	if (cur->next != NULL) {
		cur->next->prev = cur_temp;
	}
	if (cur->mem_alloc == 1) {
		free(cur->pak);
	}
	free(cur);

	return (1);
}

uint8_t
pak_list_dup_node(uint32_t no)
{
        struct pak_file_info *cur;
        struct pak_file_info *cur_temp = NULL;
	struct pak_file_info *temp;
        uint32_t pak_count = no-1;

	cur = pak_list_get(no);

        temp = (struct pak_file_info *)malloc(sizeof(struct pak_file_info));
	memcpy(temp, cur, sizeof(struct pak_file_info));	

	if (cur->mem_alloc == 1) {
		temp->pak = malloc(temp->pak_hdr.caplen);
		memcpy(temp->pak, cur->pak, temp->pak_hdr.caplen);
	} else {
		temp->mem_alloc = 0;
	}
	cur->next = temp;
	temp->prev = cur;

        return (1);
}


/* Obligatory basic callback */
static void print_hello( GtkWidget *w,
                         gpointer   data )
{
  g_message ("Hello, World!\n");
}

static void
file_save(GtkWidget *w,
          gpointer   data )
{
	FILE *fp, *fp_temp;
	struct pak_file_info *temp;

	if ((fp = fopen(f_name, "rb")) == NULL) {
		goto file_save_end;	
	}

	fp_temp = fopen("PsqCapTemp.pcap", "wb");
	fwrite((void *)&p->cap_file_hdr,sizeof(struct pcap_file_header),1,fp_temp);

	temp = po_info->next;
	while(temp)
	{
		if (temp->mem_alloc == 1) {
			fwrite((void *)&temp->pak_hdr, sizeof(struct pcap_pkthdr), 1, fp_temp);
			fwrite(temp->pak, temp->pak_len, 1, fp_temp);
		} else {
			fseek(p->rfile, temp->offset, 0);
			p->buffer = p->base;
			pcap_offline_read(p,1);
			fwrite((void *)&p->pak_hdr, sizeof(struct pcap_pkthdr), 1, fp_temp);
			fwrite(p->buffer, p->cap_len, 1, fp_temp);
		}
		temp = temp->next;
	}
	unlink(f_name);
	link("PsqCapTemp.pcap", f_name);
	unlink("PsqCapTemp.pcap");
	fclose(fp);
	fclose(fp_temp);
file_save_end:
	;
}

static void file_save_as(GtkWidget *w,
                         gpointer   data )
{
	GtkWidget *dialog;
	char *filename;
        FILE *fp, *fp_temp;
        struct pak_file_info *temp;

	dialog = gtk_file_chooser_dialog_new ("Save File",
				      GTK_WINDOW(top_level),
				      GTK_FILE_CHOOSER_ACTION_SAVE,
				      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
				      GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
				      NULL);

	if ((fp = fopen(f_name, "rb")) == NULL) {
		goto file_save_as_end;
	}

	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
  	{
    		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));

        	fp_temp = fopen(filename, "wb");
        	fwrite((void *)&p->cap_file_hdr,sizeof(struct pcap_file_header),1,fp_temp);

        	temp = po_info->next;
        	while(temp)
        	{
                	if (temp->mem_alloc == 1) {
                        	fwrite((void *)&temp->pak_hdr, sizeof(struct pcap_pkthdr), 1, fp_temp);
                        	fwrite(temp->pak, temp->pak_len, 1, fp_temp);
                	} else {
                        	fseek(p->rfile, temp->offset, 0);
                        	p->buffer = p->base;
                        	pcap_offline_read(p,1);
                        	fwrite((void *)&p->pak_hdr, sizeof(struct pcap_pkthdr), 1, fp_temp);
                        	fwrite(p->buffer, p->cap_len, 1, fp_temp);
                	}
                	temp = temp->next;
        	}
        	fclose(fp);
        	fclose(fp_temp);

    		g_free (filename);
  	}
file_save_as_end:
	gtk_widget_destroy (dialog);
}

void
time_elapsed(struct timeval *buffer, char *time)
{
        gint32 sec=0, usec=0;
        double timeelapsed;

        sec = buffer->tv_sec - tsec;
        usec = buffer->tv_usec - tusec;
        timeelapsed = (double)usec/1000000 + (double)sec;

        sprintf(time,"%f",timeelapsed);
}

void
append_pl_tree_data(int no, const char *time, const char *srcip, const char *dstip, char *proto, char *info, char *color, gboolean color_set)
{

        gtk_tree_store_append (pl_store, &pl_iter, NULL);
        gtk_tree_store_set (pl_store, &pl_iter, 0, no, 1, time,
                2, srcip, 3, dstip, 4, proto, 5, info, 6, color, -1);

}

void
append_hex_data(char *hex_data, uint16_t len)
{
        uint16_t i;
        char buf[10];
        u_char *ch;
        ch = hex_data;
        uint16_t offset = 0;

        sprintf(buf, "%05d", offset);
        gtk_text_buffer_insert_at_cursor (hex_buffer, buf , -1);

        sprintf(buf, "  ");
        gtk_text_buffer_insert_at_cursor (hex_buffer, buf , -1);

        for (i = 0; i < len; i++) {
                sprintf(buf,"%02X  ",*ch);
                gtk_text_buffer_insert_at_cursor (hex_buffer, buf , -1);
                ch++;

                if ((((i+1) % 8) == 0)) {
                        if (((i+1) % 16) == 0) {
                                sprintf(buf, "\n");
                                gtk_text_buffer_insert_at_cursor (hex_buffer, buf , -1);
                                offset += 10;
                                sprintf(buf, "%05d", offset);
                                gtk_text_buffer_insert_at_cursor (hex_buffer, buf , -1);
                                sprintf(buf, "  ");
                                gtk_text_buffer_insert_at_cursor (hex_buffer, buf , -1);

                        } else {
                                sprintf(buf, "   ");
                                gtk_text_buffer_insert_at_cursor (hex_buffer, buf , -1);
                        }
                }

        }

}


void
p_display_modified()
{
    GtkTextIter start, end;

    if (fpak_curr_info->mem_alloc == 0) {
        fseek(p->rfile,fpak_curr_info->offset,0);
        p->buffer = p->base;
        pcap_offline_read(p,1);
    } else {
        p->buffer = fpak_curr_info->pak;
        p->cap_len = fpak_curr_info->pak_len;
    }

    gtk_tree_store_clear(p_store);

    gtk_text_buffer_get_start_iter(hex_buffer, &start);
    gtk_text_buffer_get_end_iter(hex_buffer, &end);
    gtk_text_buffer_delete(hex_buffer, &start, &end);

    display_p_tree_data(p->buffer);
    append_hex_data(p->buffer,p->cap_len);

}


void
pl_display_modified_iter()
{
        uint32_t i = 0;
        struct pl_decap_pak_info pak_info;
        struct pak_file_info *temp_file_pak_info = po_info;
        char time[40];

        pak_info.src_mac = NULL;
        pak_info.dst_mac = NULL;
        pak_info.src_ip = NULL;
        pak_info.dst_ip = NULL;
        pak_info.proto = 0;
        pak_info.eth_proto = 0;
        gtk_tree_store_clear(pl_store);
        while(temp_file_pak_info = temp_file_pak_info->next) {
                i++;
		if ((i == 1) && (fpak_curr_info == NULL)) {
			fpak_curr_info = temp_file_pak_info;
		}
                if (temp_file_pak_info->mem_alloc == 1) {
                        p->buffer = temp_file_pak_info->pak;
                        p->cap_len = temp_file_pak_info->pak_len;
                } else {
                        fseek(p->rfile,temp_file_pak_info->offset,0);
                        p->buffer = p->base;
                        pcap_offline_read(p,1);
                }
                if (!pl_decap_pak(p->buffer,&pak_info)) {
                        time_elapsed(&(temp_file_pak_info->pak_hdr.ts), time);
                        append_pl_tree_data (i, time,
                                pak_info.src_mac, pak_info.dst_mac, pak_info.protocol, pak_info.info, pak_info.row_color, TRUE);
                } else {
                        time_elapsed(&(temp_file_pak_info->pak_hdr.ts), time);
                        append_pl_tree_data (i, time,
                                pak_info.src_ip, pak_info.dst_ip, pak_info.protocol, pak_info.info, pak_info.row_color, TRUE);
                }
                free_pl_decap_pak_info(&pak_info);
                temp_file_pak_info->pak_no = i;
        }
	p_display_modified();
}

static void
convert_to_ipv6 (GtkWidget *w,
          gpointer   data )
{
	struct pak_file_info *fpak_info = NULL;
	struct pak_file_info *fpak_curr_next = NULL;

        if (p == NULL) {
                goto ipv6_end;
        }

	fpak_info = pak_list_get(1);
	for (; fpak_info  != NULL; ) {
		fpak_curr_next = fpak_info->next;
		to_ipv6(fpak_info);
		fpak_info = fpak_curr_next;
	}
	pl_display_modified_iter();	
ipv6_end:
	;
}

static void
add_mpls_tag (GtkWidget *w,
          gpointer   data )
{
        GtkWidget *dialog, *table, *label, *exp, *stack, *ttl;
        GtkWidget *lbl1, *lbl2, *lbl3, *lbl4;
        gint result;
        char *s_val;
        const gchar *p_label, *p_exp, *p_stack, *p_ttl;
        uint32_t i;
        uint16_t label_val = 10, exp_val = 0, stack_val = 1, ttl_val = 64;
        struct pak_file_info *fpak_info;

	if (p == NULL) {
		goto mtag_end;
	}
        dialog = gtk_dialog_new_with_buttons ("MPLS values", NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_STOCK_OK, GTK_RESPONSE_OK,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                NULL);

        gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
        /* Create four entries that will tell the user what data to enter. */
        lbl1 = gtk_label_new ("MPLS Label:");
        lbl2 = gtk_label_new ("MPLS Experimental Bits:");
        lbl3 = gtk_label_new ("MPLS Bottom Of Label Stack:");
	lbl4 = gtk_label_new ("MPLS TTL:");

        label    = gtk_entry_new ();
        exp      = gtk_entry_new ();
        stack    = gtk_entry_new ();
	ttl	 = gtk_entry_new ();

        //get_stream_values();
        /* Retrieve the user's information for the default values. */
        gtk_entry_set_text (GTK_ENTRY (label), "10");
        gtk_entry_set_text (GTK_ENTRY (exp), "0");
        gtk_entry_set_text (GTK_ENTRY (stack), "1");
	gtk_entry_set_text (GTK_ENTRY (ttl), "64");

        table = gtk_table_new (4, 2, FALSE);

        gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl2, 0, 1, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl3, 0, 1, 2, 3);
	gtk_table_attach_defaults (GTK_TABLE (table), lbl4, 0, 1, 3, 4);
        gtk_table_attach_defaults (GTK_TABLE (table), label, 1, 2, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), exp, 1, 2, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), stack, 1, 2, 2, 3);
	gtk_table_attach_defaults (GTK_TABLE (table), ttl, 1, 2, 3, 4);
        gtk_table_set_row_spacings (GTK_TABLE (table), 5);
        gtk_table_set_col_spacings (GTK_TABLE (table), 5);
        gtk_container_set_border_width (GTK_CONTAINER (table), 5);
        gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
        gtk_widget_show_all (dialog);

        /* Run the dialog and output the data if the user clicks the OK button. */
        result = gtk_dialog_run (GTK_DIALOG (dialog));
        if (result == GTK_RESPONSE_OK)
        {
                p_label     =  gtk_entry_get_text (GTK_ENTRY (label));
                p_exp       =  gtk_entry_get_text (GTK_ENTRY (exp));
                p_stack     =  gtk_entry_get_text (GTK_ENTRY (stack));
		p_ttl       =  gtk_entry_get_text (GTK_ENTRY (ttl));

                label_val = atoi(p_label);
                exp_val   = atoi(p_exp);
                stack_val = atoi(p_stack);
		ttl_val	  = atoi(p_ttl);	

                err_val = 0;
                fpak_info = pak_list_get(1);
                for (; fpak_info != NULL; ) {
                        add_mtag(fpak_info, label_val, exp_val, stack_val, ttl_val);
                        fpak_info = fpak_info->next;
                }
                pl_display_modified_iter();
        }
        gtk_widget_destroy (dialog);
mtag_end:
	;
}

static void
add_vlan_tag (GtkWidget *w,
          gpointer   data )
{
        GtkWidget *dialog, *table, *priority, *cfi, *id;
        GtkWidget *lbl1, *lbl2, *lbl3;
        gint result;
        char *s_val;
        const gchar *p_priority, *p_cfi, *p_id;
        uint32_t i;
	uint16_t priority_val = 0, cfi_val = 0, id_val = 100;
	struct pak_file_info *fpak_info;

	if (p == NULL) {
		goto vtag_end;
	}
        dialog = gtk_dialog_new_with_buttons ("VLAN values", NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_STOCK_OK, GTK_RESPONSE_OK,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                NULL);

        gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
        /* Create four entries that will tell the user what data to enter. */
        lbl1 = gtk_label_new ("Priority:");
        lbl2 = gtk_label_new ("CFI:");
        lbl3 = gtk_label_new ("VLAN ID:");

        priority   = gtk_entry_new ();
        cfi   = gtk_entry_new ();
        id    = gtk_entry_new ();

        //get_stream_values();
        /* Retrieve the user's information for the default values. */
        gtk_entry_set_text (GTK_ENTRY (priority), "0");
        gtk_entry_set_text (GTK_ENTRY (cfi), "0");
        gtk_entry_set_text (GTK_ENTRY (id), "100");

        table = gtk_table_new (3, 2, FALSE);

        gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl2, 0, 1, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl3, 0, 1, 2, 3);
        gtk_table_attach_defaults (GTK_TABLE (table), priority, 1, 2, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), cfi, 1, 2, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), id, 1, 2, 2, 3);
        gtk_table_set_row_spacings (GTK_TABLE (table), 5);
        gtk_table_set_col_spacings (GTK_TABLE (table), 5);
        gtk_container_set_border_width (GTK_CONTAINER (table), 5);
        gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
        gtk_widget_show_all (dialog);

        /* Run the dialog and output the data if the user clicks the OK button. */
        result = gtk_dialog_run (GTK_DIALOG (dialog));
        if (result == GTK_RESPONSE_OK)
        {
                p_priority  =  gtk_entry_get_text (GTK_ENTRY (priority));
                p_cfi       =  gtk_entry_get_text (GTK_ENTRY (cfi));
                p_id        =  gtk_entry_get_text (GTK_ENTRY (id));

		priority_val = atoi(p_priority);
		cfi_val	     = atoi(p_cfi);
		id_val	     = atoi(p_id);

                err_val = 0;
		fpak_info = pak_list_get(1);
                for (; fpak_info != NULL; ) {
			add_vtag(fpak_info, priority_val, cfi_val, id_val);
			fpak_info = fpak_info->next;
                }
                pl_display_modified_iter();
        }
        gtk_widget_destroy (dialog);
vtag_end:
	;
}

static void
fragment_packets (GtkWidget *w,
          gpointer   data )
{
	GtkWidget *dialog, *table, *w_frag_size;
	GtkWidget *lbl1;
	gint result;
	gchar *p_frag_size, *f_val;
	uint16_t fsize = 8;
	struct pak_file_info *fpak_curr_next = NULL;

	if (p == NULL) {
		goto frag_end;
	}

        dialog = gtk_dialog_new_with_buttons ("Fragment Options", NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_STOCK_OK, GTK_RESPONSE_OK,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
	
	lbl1 = gtk_label_new ("Fragment Size:");
	w_frag_size   = gtk_entry_new ();

	gtk_entry_set_text (GTK_ENTRY (w_frag_size), "8");

	table = gtk_table_new (1, 2, FALSE);

	gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
	gtk_table_attach_defaults (GTK_TABLE (table), w_frag_size, 1, 2, 0, 1);

	gtk_container_set_border_width (GTK_CONTAINER (table), 5);
	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
	gtk_widget_show_all (dialog);

	result = gtk_dialog_run (GTK_DIALOG (dialog));
	if (result == GTK_RESPONSE_OK)
	{
		p_frag_size = (gchar *)gtk_entry_get_text (GTK_ENTRY (w_frag_size));
		fsize = atoi(p_frag_size);
		err_val = 0;
		fpak_curr_info = pak_list_get(1);
		for (; fpak_curr_info  != NULL; ) {
			fpak_curr_next = fpak_curr_info->next;
			frag_pak(fpak_curr_info, fsize);
			fpak_curr_info = fpak_curr_next;
		}			

	}
	pl_display_modified_iter();
	gtk_widget_destroy (dialog);
	
frag_end:
	;
}

void
append_p_tree_data(char *param, char *value, uint8_t level, uint16_t p_ref_proto, int rl1, int rl2)
{
        /* Add the category as a new root element. */
        if (level == 0) {
                gtk_tree_store_append (p_store, &p_iter, NULL);
                gtk_tree_store_set (p_store, &p_iter, 0, param, -1);
        }

        if (level == 1) {
                gtk_tree_store_append (p_store, &p_child, &p_iter);
                gtk_tree_store_set (p_store, &p_child, 0, param, 1, value, 2, p_ref_proto, 3, rl1, 4, rl2, -1);
        }

	if (level == 2) {
                gtk_tree_store_append (p_store, &p_child1, &p_child);
                gtk_tree_store_set (p_store, &p_child1, 0, param, 1, value, 2, p_ref_proto, 3, rl1, 4, rl2, -1);
	}
}

void
ptree_append(char *param, void *value, uint8_t type, uint8_t level, uint16_t p_ref_proto, uint16_t record_no, ...)
{
	char buf[100];
	char *temp_val;
	int rl1 = 0,rl2 = 0;
	va_list ap;

	va_start(ap, record_no);
	if (record_no == 2) {
		rl1 = va_arg(ap, int);
		rl2 = va_arg(ap, int);
	} else {
		rl1 = va_arg(ap, int);
	}	

	if (type == MAC) {
		temp_val = (char *)ether_to_str((uint8_t *)value);
        	sprintf(buf,"%s",temp_val);
		free(temp_val);
	} else if (type == UINT16_HEX) {
		sprintf(buf, "0x%04x", ntohs(*(uint16_t *)value));
	} else if (type == UINT16D) {
		sprintf(buf, "%u", *((uint16_t *)value));
	} else if (type == UINT16) {
		sprintf(buf,"%u",ntohs(*((uint16_t *)value)));
	} else if (type == UINT16HD) {
                sprintf(buf,"%u", *((uint16_t *)value));
	} else if (type == UINT8) {
		sprintf(buf, "%u", *((uint8_t *)value));
	} else if(type == UINT8_HEX_2) {
		sprintf(buf, "0x%02x", *(uint8_t *)value);
        } else if(type == UINT8_HEX_1) {
                sprintf(buf, "0x%d", *(uint8_t *)value);
	} else if (type == UINT32) {
		sprintf(buf, "%u", ntohl(*((uint32_t *)value)));
        } else if (type == UINT32D) {
                sprintf(buf, "%u", *((uint32_t *)value));
        } else if (type == UINT32_HEX) {
                sprintf(buf, "0x%08x", ntohl(*((uint32_t *)value)));
        } else if (type == UINT32_HEX_5) {
                sprintf(buf, "0x%05x", *((uint32_t *)value));
	} else if (type == STRING) {
		sprintf(buf," ");
        } else if (type == STRING_P) {
                sprintf(buf,"%s", value);
	} else if (type == IPV4_ADDR) {
		temp_val = (char *)ip_to_str((uint8_t *)value);
		sprintf(buf, "%s", temp_val);
		free(temp_val);
	}else if (type == IPV6_ADDR) {
        	inet_ntop(AF_INET6, value, buf, 128);
        }
	append_p_tree_data(param,buf,level,p_ref_proto,rl1,rl2);

}

void
display_p_tree_data(uint8_t *pak)
{

	display_pak(pak);

}

void
print_hex_ascii_line(const u_char *payload, int len)
{

        int i;
        int gap;
        const u_char *ch;

        /* offset */
        //printf("%05d   ", offset);

        /* hex */
        ch = payload;
        for(i = 0; i < len; i++) {
                printf("%02x ", *ch);
                ch++;
                /* print extra space after 8th byte for visual aid */
                if (i == 7)
                        printf(" ");
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
                printf(" ");

        /* fill hex gap with spaces if not full line */
        if (len < 16) {
                gap = 16 - len;
                for (i = 0; i < gap; i++) {
                        printf("   ");
                }
        }
        printf("   ");

        /* ascii (if printable) */
        ch = payload;
        for(i = 0; i < len; i++) {
                if (isprint(*ch))
                        printf("%c", *ch);
                else
                        printf(".");
                ch++;
        }

        printf("\n");

return;
}

uint8_t
display_pcap(char *filename)
{
	struct pl_decap_pak_info *pak_info;
	guint i = 1;
	struct pak_file_info *current;
	uint32_t offset;
	GtkTextIter start, end;
	char time[40];

	pak_info = malloc_pl_decap_pak_info();
	if (p != NULL) {
		free_pcapt(p);
	}
	pak_list_free();
	p = (pcap_t *)pcap_open(filename);
	if (p == NULL) {
		return -1;
	}
	gtk_tree_store_clear(pl_store);  
	for (offset = ftell(p->rfile);pcap_offline_read(p,1);offset = ftell(p->rfile)) {
		if (i == 1) {
			current = pak_list_add(&po_info,offset, i);
			fpak_curr_info = current;
			gtk_tree_store_clear(p_store);

			gtk_text_buffer_get_start_iter(hex_buffer, &start);
			gtk_text_buffer_get_end_iter(hex_buffer, &end);
			gtk_text_buffer_delete(hex_buffer, &start, &end);

			display_p_tree_data(p->buffer);
			append_hex_data(p->buffer,p->cap_len);

			tsec  = p->pak_hdr.ts.tv_sec;
			tusec = p->pak_hdr.ts.tv_usec;
		} else {
			current = pak_list_add(&current, offset, i);
		}
                if (!pl_decap_pak(p->buffer,pak_info)) {
			time_elapsed(&(p->pak_hdr.ts), time);
                        append_pl_tree_data (i, time,
                                pak_info->src_mac, pak_info->dst_mac, pak_info->protocol, pak_info->info, pak_info->row_color, TRUE);
                } else {
			time_elapsed(&(p->pak_hdr.ts), time);
                        append_pl_tree_data (i, time,
                                pak_info->src_ip, pak_info->dst_ip, pak_info->protocol, pak_info->info, pak_info->row_color, TRUE);
                }

		free_pl_decap_pak_info(pak_info);
		i++;
	}
	fseek(p->rfile,fpak_curr_info->offset,0);
	pcap_offline_read(p,1);
}

void
pl_display_modified_list()
{
	uint32_t i = 0;
	struct pl_decap_pak_info pak_info;
	char time[40];

	gtk_tree_store_clear(pl_store);
	for (i = 1; (fpak_curr_info = pak_list_get(i)) != NULL ; i++) {
		if (fpak_curr_info->pak != NULL) {
			p->buffer = fpak_curr_info->pak;
			p->cap_len = fpak_curr_info->pak_len;
		} else { 
                        fseek(p->rfile,fpak_curr_info->offset,0);
                        p->buffer = p->base;
                        pcap_offline_read(p,1);
		}
                if (!pl_decap_pak(p->buffer,&pak_info)) {
			time_elapsed(&(fpak_curr_info->pak_hdr.ts), time);
                       	append_pl_tree_data (i, time,
                               	pak_info.src_mac, pak_info.dst_mac, pak_info.protocol, pak_info.info, pak_info.row_color, TRUE);
               	} else {
			time_elapsed(&(fpak_curr_info->pak_hdr.ts), time);
                       	append_pl_tree_data (i, time,
                               	pak_info.src_ip, pak_info.dst_ip, pak_info.protocol, pak_info.info, pak_info.row_color, TRUE);
               	}
		free_pl_decap_pak_info(&pak_info);
	}
}

void
file_open_cmd_cb(GtkWidget *w, gpointer data) {
	GtkWidget *win;
	char *fname;

	win = gtk_file_chooser_dialog_new("Open pcap file", GTK_WINDOW(top_level), GTK_FILE_CHOOSER_ACTION_OPEN, 
				      GTK_STOCK_CANCEL,
     				      GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN,
     				      GTK_RESPONSE_OK,
     				      NULL);
	     
        if (gtk_dialog_run (GTK_DIALOG (win)) == GTK_RESPONSE_OK)
        {
        	fname = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (win));
		strcpy(f_name,fname);
        	display_pcap (f_name);
        	g_free (fname);
        }
     gtk_widget_destroy (win);
}
/* Our menu, an array of GtkItemFactoryEntry structures that defines each menu item */
static GtkItemFactoryEntry menu_items[] = {
  { "/_File",         NULL,         NULL,           0, "<Branch>" },
  { "/File/_Open...", "<control>O", file_open_cmd_cb,
                             0, "<StockItem>", GTK_STOCK_OPEN},
  { "/File/_Save",    "<control>S", file_save,    0, "<StockItem>", GTK_STOCK_SAVE },
  { "/File/Save _As", "<shift><control>S", file_save_as, 0, "<StockItem>",GTK_STOCK_SAVE_AS },
  { "/File/sep1",     NULL,         NULL,           0, "<Separator>" },
  { "/File/_Quit",    "<CTRL>Q", gtk_main_quit, 0, "<StockItem>", GTK_STOCK_QUIT },
  { "/_Edit",         NULL,         NULL,           0, "<Branch>" },
  { "/Edit/_Add VLAN Tag (All Packets)",    "<control>V", add_vlan_tag, 0, "<Item>", NULL},
  { "/Edit/_Add MPLS Tag (All IPv4 Packets)",    "<control>M", add_mpls_tag, 0, "<Item>", NULL},
  { "/Edit/_Convert To IPv6 (All IPv4 Packets)",    "<control>6", convert_to_ipv6, 0, "<Item>", NULL},
  { "/Edit/_Fragment Packets (All IPv4 Packets)",    "<control>F", fragment_packets, 0, "<Item>", NULL},
  { "/_Help",         NULL,         NULL,           0, "<Branch>" },
  { "/_Help/About",   NULL,         NULL,           0, "<Item>" },
};

static gint nmenu_items = sizeof (menu_items) / sizeof (menu_items[0]);

static void
cell_data_func (GtkTreeViewColumn *column,
		GtkCellRenderer *renderer,
		GtkTreeModel *model,
		GtkTreeIter *iter,
		gpointer data)
{
	gchar *text;
	/* Get the color string stored by the column and make it the foreground color. */
	gtk_tree_model_get (model, iter, 6, &text, -1);
	//g_object_set (renderer, "foreground", "#FFFFFF", "foreground-set", TRUE,
	//	"background", text, "background-set", TRUE, NULL);
        g_object_set (renderer, "background", text, "background-set", TRUE, NULL);
	g_free (text);
}


static void
setup_pl_tree_view (GtkWidget *treeview)
{
   GtkCellRenderer *renderer;
   GtkTreeViewColumn *column;
   /* Create a new GtkCellRendererText, add it to the tree view column and
 *  *  *     * append the column to the tree view. */
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes
                           ("No.", renderer, "text", 0, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);
   g_object_set(renderer,
               "weight", PANGO_WEIGHT_NORMAL,
               "weight-set", TRUE,
               NULL);
   g_object_set(renderer,
               "scale", PANGO_SCALE_MEDIUM,
               "scale-set", TRUE,
               NULL);
   gtk_tree_view_column_set_cell_data_func (column, renderer,
   cell_data_func, NULL, NULL);
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes
                           ("Time", renderer, "text", 1, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);
   g_object_set(renderer,
               "weight", PANGO_WEIGHT_NORMAL,
               "weight-set", TRUE,
               NULL);
   g_object_set(renderer,
               "scale", PANGO_SCALE_MEDIUM,
               "scale-set", TRUE,
               NULL);
   gtk_tree_view_column_set_cell_data_func (column, renderer,
   cell_data_func, NULL, NULL);
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes
                           ("source", renderer, "text", 2, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);
   g_object_set(renderer,
               "weight", PANGO_WEIGHT_NORMAL,
               "weight-set", TRUE,
               NULL);
   g_object_set(renderer,
               "scale", PANGO_SCALE_MEDIUM,
               "scale-set", TRUE,
               NULL);
   gtk_tree_view_column_set_cell_data_func (column, renderer,
   cell_data_func, NULL, NULL);
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes
                           ("destination", renderer, "text", 3, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);
   g_object_set(renderer,
               "weight", PANGO_WEIGHT_NORMAL,
               "weight-set", TRUE,
               NULL);
   g_object_set(renderer,
               "scale", PANGO_SCALE_MEDIUM,
               "scale-set", TRUE,
               NULL);
   gtk_tree_view_column_set_cell_data_func (column, renderer,
   cell_data_func, NULL, NULL);
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes
                           ("protocol", renderer, "text", 4, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);
   g_object_set(renderer,
               "weight", PANGO_WEIGHT_NORMAL,
               "weight-set", TRUE,
               NULL);
   g_object_set(renderer,
               "scale", PANGO_SCALE_MEDIUM,
               "scale-set", TRUE,
               NULL);
   gtk_tree_view_column_set_cell_data_func (column, renderer,
   cell_data_func, NULL, NULL);
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes
                           ("Info", renderer, "text", 5, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);
   g_object_set(renderer,
               "weight", PANGO_WEIGHT_NORMAL,
               "weight-set", TRUE,
               NULL);
   g_object_set(renderer,
               "scale", PANGO_SCALE_MEDIUM,
               "scale-set", TRUE,
               NULL);
   gtk_tree_view_column_set_cell_data_func (column, renderer,
   cell_data_func, NULL, NULL);
}

static void
cell_edited (GtkCellRendererText *renderer,
		gchar *path,
		gchar *new_text,
		GtkTreeView *treeview)
{
	GtkTreePath *pl_path;
	GtkTreeIter iter;
	GtkTreeModel *model;
	struct pl_decap_pak_info *pak_info;
	char time[40];
	gint i;
	struct pak_file_info *fpak_temp;
	
	fpak_temp = fpak_curr_info;
	pak_info = malloc_pl_decap_pak_info();
	if (g_ascii_strcasecmp (new_text, "") != 0)
	{
		model = gtk_tree_view_get_model (treeview);
		if (gtk_tree_model_get_iter_from_string (model, &iter, path)) {
			if (fpak_curr_info->mem_alloc == 0) {
                                fseek(p->rfile,fpak_curr_info->offset,0);
                                p->buffer = p->base;
                                pcap_offline_read(p,1);
				fpak_curr_info->pak = malloc(p->cap_len);
    				memcpy(fpak_curr_info->pak,p->buffer,p->cap_len);
				fpak_curr_info->pak_len = p->cap_len;
				fpak_curr_info->mem_alloc = 1;
			}
			err_val = 0;
			update_pak(new_text);
			p->buffer = fpak_curr_info->pak;
			error_val();
			if (err_val == 0) {
				gtk_tree_store_set (GTK_TREE_STORE (model), &iter, 1, new_text, -1);
				p_display_modified();

				/*model = gtk_tree_view_get_model (GTK_TREE_VIEW(pl_treeview));
				gtk_tree_model_get_iter_from_string (model, &pl_iter, "0");
				do
				{
					gtk_tree_model_get (model, &pl_iter, 0, &i, -1);
					if (i == fpak_curr_info->pak_no)
					{
						break;
					}
				} while (gtk_tree_model_iter_next (model, &pl_iter));
				pl_path = gtk_tree_model_get_path (model, &pl_iter);
				
		                if (!pl_decap_pak(p->buffer,pak_info)) {
                		        time_elapsed(&(p->pak_hdr.ts), time);
                        		append_pl_tree_data (i, time,
                                		pak_info->src_mac, pak_info->dst_mac, pak_info->protocol, pak_info->info, pak_info->row_color, TRUE);
                		} else {
                        		time_elapsed(&(p->pak_hdr.ts), time);
                        		append_pl_tree_data (i, time,
                                		pak_info->src_ip, pak_info->dst_ip, pak_info->protocol, pak_info->info, pak_info->row_color, TRUE);
                		} */
				pl_display_modified_iter();

			}
		}
	}
	fpak_curr_info = fpak_temp;
	free_pl_decap_pak_info(pak_info);
	gtk_tree_view_expand_all (GTK_TREE_VIEW (p_treeview));
}

static void
setup_p_tree_view (GtkWidget *treeview)
{
   GtkCellRenderer *renderer;
   GtkTreeViewColumn *column;
   /* Create a new GtkCellRendererText, add it to the tree view column and
 *  *  *     * append the column to the tree view. */
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes
                           ("parameter", renderer, "text", 0, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);


   renderer = gtk_cell_renderer_text_new ();
   g_object_set (renderer, "editable", TRUE, "editable-set", TRUE, NULL);
   g_signal_connect (G_OBJECT (renderer), "edited",
	G_CALLBACK (cell_edited),
	(gpointer) treeview);
   column = gtk_tree_view_column_new_with_attributes
                           ("value", renderer, "text", 1, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);

}


void
show_main_window(void)
{
        gtk_widget_show_all (top_level);
	gtk_window_set_policy(GTK_WINDOW(top_level), TRUE, TRUE, FALSE);

        gtk_main ();
}

void
create_menubar(void)
{
        GtkWidget *menubar;
	GtkItemFactory *item_factory;
	GtkAccelGroup *accel_group;

        /* Make an accelerator group (shortcut keys) */
        accel_group = gtk_accel_group_new ();

        /* Make an ItemFactory (that makes a menubar) */
        item_factory = gtk_item_factory_new (GTK_TYPE_MENU_BAR, "<main>",
                                      accel_group);

        /* This function generates the menu items. Pass the item factory,
 *         *      the number of items in the array, the array itself, and any
 *                 *           callback data for the the menu items. */
        gtk_item_factory_create_items (item_factory, nmenu_items, menu_items, NULL);

        /* Attach the new accelerator group to the window. */
        gtk_window_add_accel_group (GTK_WINDOW (top_level), accel_group);

        /* Finally, return the actual menu bar created by the item factory. */
        menubar = gtk_item_factory_get_widget (item_factory, "<main>");

        gtk_box_pack_start (GTK_BOX (mn_vbox), menubar,FALSE, TRUE, 0);

}

void
create_top_window(void)
{
	GError *err;	

        top_level = gtk_window_new (GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title (GTK_WINDOW (top_level), "PacketSQuare-Capedit");
	gtk_window_set_default_icon_from_file("pkts.png", &err);
        gtk_container_set_border_width (GTK_CONTAINER (top_level), 0);
        gtk_window_maximize(GTK_WINDOW(top_level));
	gtk_window_set_resizable(GTK_WINDOW(top_level), TRUE);
	g_signal_connect (G_OBJECT (top_level), "delete_event",
                      G_CALLBACK (gtk_main_quit), NULL);

}

pl_cur_changed(GtkTreeView *treeview)
{
  GtkTreeSelection *selection;
  GtkTreeModel     *model;
  GtkTreeIter       iter;
  GtkTextIter start, end;


  /* This will only work in single or browse selection mode! */
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
  if (gtk_tree_selection_get_selected(selection, &model, &iter))
  {
    gint no;

    if (fpak_curr_info->mem_alloc == 0) {
	    fpak_curr_info->pak = NULL;
    }
    gtk_tree_model_get (model, &iter, 0, &no, -1);
    fpak_curr_info  = pak_list_get(no);
    if (fpak_curr_info->mem_alloc == 0) {
    	fseek(p->rfile,fpak_curr_info->offset,0);    
	    p->buffer = p->base;
    	pcap_offline_read(p,1);
    } else {
	    p->buffer = fpak_curr_info->pak;
	    p->cap_len = fpak_curr_info->pak_len;
    }
    
    gtk_tree_store_clear(p_store);

    gtk_text_buffer_get_start_iter(hex_buffer, &start);
    gtk_text_buffer_get_end_iter(hex_buffer, &end);
    gtk_text_buffer_delete(hex_buffer, &start, &end);

    display_p_tree_data(p->buffer);
    gtk_tree_view_expand_all (GTK_TREE_VIEW (p_treeview));
    append_hex_data(p->buffer,p->cap_len);
  }
}

void
pl_view_popup_menu_stream_change (GtkWidget *menuitem, gpointer userdata)
{
    /* we passed the view as userdata when we connected the signal */
    //GtkTreeView *treeview = GTK_TREE_VIEW(userdata);
	struct stream_values;
	GtkWidget *dialog, *table, *src_mac, *dst_mac, *src_ip, *dst_ip, *src_port, *dst_port;
	GtkWidget *lbl1, *lbl2, *lbl3, *lbl4, *lbl5, *lbl6;
	gint result;
	char *s_val;
	const gchar *p_src_mac, *p_dst_mac, *p_src_ip, *p_dst_ip, *p_src_port, *p_dst_port;
	uint32_t i;
	char port[6];
	dialog = gtk_dialog_new_with_buttons ("Edit Stream values", NULL,
						GTK_DIALOG_MODAL,
						GTK_STOCK_OK, GTK_RESPONSE_OK,
						GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
						NULL);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
	/* Create four entries that will tell the user what data to enter. */
	lbl1 = gtk_label_new ("Source MAC:");
	lbl2 = gtk_label_new ("Destination MAC:");
	lbl3 = gtk_label_new ("Source IP:");
	lbl4 = gtk_label_new ("Destination IP:");
	lbl5 = gtk_label_new ("Source Port:");
	lbl6 = gtk_label_new ("Destination Port:");
	
	src_mac   = gtk_entry_new ();
	dst_mac   = gtk_entry_new ();
	src_ip    = gtk_entry_new ();
	dst_ip    = gtk_entry_new ();
	src_port  = gtk_entry_new ();
	dst_port  = gtk_entry_new ();

	//get_stream_values();
	/* Retrieve the user's information for the default values. */
	s_val = (char *)ether_to_str(cur_pak_info.src_mac);
	gtk_entry_set_text (GTK_ENTRY (src_mac), s_val);
	free(s_val);
	s_val = (char *)ether_to_str(cur_pak_info.dst_mac);
	gtk_entry_set_text (GTK_ENTRY (dst_mac), s_val);
	free(s_val);
	s_val = (char *)ip_to_str((uint8_t *)&cur_pak_info.src_ip);
	gtk_entry_set_text (GTK_ENTRY (src_ip), s_val);
	free(s_val);
	s_val = (char *)ip_to_str((uint8_t *)&cur_pak_info.dst_ip);
	gtk_entry_set_text (GTK_ENTRY (dst_ip), s_val);
	free(s_val);
	itoa(ntohs(cur_pak_info.src_port), port, 10);
        gtk_entry_set_text (GTK_ENTRY (src_port), port);
	itoa(ntohs(cur_pak_info.dst_port), port, 10);
        gtk_entry_set_text (GTK_ENTRY (dst_port), port);

	table = gtk_table_new (6, 2, FALSE);

	gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
	gtk_table_attach_defaults (GTK_TABLE (table), lbl2, 0, 1, 1, 2);
	gtk_table_attach_defaults (GTK_TABLE (table), lbl3, 0, 1, 2, 3);
	gtk_table_attach_defaults (GTK_TABLE (table), lbl4, 0, 1, 3, 4);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl5, 0, 1, 4, 5);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl6, 0, 1, 5, 6);
	gtk_table_attach_defaults (GTK_TABLE (table), src_mac, 1, 2, 0, 1);
	gtk_table_attach_defaults (GTK_TABLE (table), dst_mac, 1, 2, 1, 2);
	gtk_table_attach_defaults (GTK_TABLE (table), src_ip, 1, 2, 2, 3);
	gtk_table_attach_defaults (GTK_TABLE (table), dst_ip, 1, 2, 3, 4);
        gtk_table_attach_defaults (GTK_TABLE (table), src_port, 1, 2, 4, 5);
        gtk_table_attach_defaults (GTK_TABLE (table), dst_port, 1, 2, 5, 6);
	gtk_table_set_row_spacings (GTK_TABLE (table), 5);
	gtk_table_set_col_spacings (GTK_TABLE (table), 5);
	gtk_container_set_border_width (GTK_CONTAINER (table), 5);
	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
	gtk_widget_show_all (dialog);

	/* Run the dialog and output the data if the user clicks the OK button. */
	result = gtk_dialog_run (GTK_DIALOG (dialog));
	if (result == GTK_RESPONSE_OK)
	{
		p_src_mac  =  gtk_entry_get_text (GTK_ENTRY (src_mac));
		p_dst_mac  =  gtk_entry_get_text (GTK_ENTRY (dst_mac));
		p_src_ip   =  gtk_entry_get_text (GTK_ENTRY (src_ip));
		p_dst_ip   =  gtk_entry_get_text (GTK_ENTRY (dst_ip));
		p_src_port =  gtk_entry_get_text (GTK_ENTRY (src_port));
		p_dst_port =  gtk_entry_get_text (GTK_ENTRY (dst_port));

		err_val = 0;
		for (i = 1; (fpak_curr_info = pak_list_get(i)) != NULL; i++) {
			if (fpak_curr_info->mem_alloc == 0) {
				fseek(p->rfile,fpak_curr_info->offset,0);
				p->buffer = p->base;
				pcap_offline_read(p,1);
                                fpak_curr_info->pak = p->buffer;
                                fpak_curr_info->pak_len = p->cap_len;
			}
			if(update_stream(p_src_mac, p_dst_mac, p_src_ip, p_dst_ip, p_src_port, p_dst_port)) {
				if (fpak_curr_info->mem_alloc == 0) {
					fpak_curr_info->pak = malloc(p->cap_len);
                                	memcpy(fpak_curr_info->pak,p->buffer,p->cap_len);
					fpak_curr_info->mem_alloc = 1;
                                	fpak_curr_info->pak_len = p->cap_len;
				}
			} else {
				if (fpak_curr_info->mem_alloc == 0) {
					fpak_curr_info->pak = NULL;
				}
			}
			if (err_val != 0) {
				error_val();
				goto stream_change_end;
			}
		}
		pl_display_modified_iter();
	}
stream_change_end:
	gtk_widget_destroy (dialog);
}
 
void
pl_view_popup_menu_mac_ip_change (GtkWidget *menuitem, gpointer userdata)
{
    /* we passed the view as userdata when we connected the signal */
    //GtkTreeView *treeview = GTK_TREE_VIEW(userdata);
        struct stream_values;
        GtkWidget *dialog, *table, *src_mac, *dst_mac, *src_ip, *dst_ip;
        GtkWidget *lbl1, *lbl2, *lbl3, *lbl4;
        gint result;
        char *s_val;
        const gchar *p_src_mac, *p_dst_mac, *p_src_ip, *p_dst_ip;
        uint32_t i;
        char port[6];

        dialog = gtk_dialog_new_with_buttons ("Replace MAC, IP Addresses", NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_STOCK_OK, GTK_RESPONSE_OK,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                NULL);

        gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
        /* Create four entries that will tell the user what data to enter. */
        lbl1 = gtk_label_new ("Source MAC:");
        lbl2 = gtk_label_new ("Destination MAC:");
        lbl3 = gtk_label_new ("Source IP:");
        lbl4 = gtk_label_new ("Destination IP:");
        
        src_mac   = gtk_entry_new ();
        dst_mac   = gtk_entry_new ();
        src_ip    = gtk_entry_new ();
        dst_ip    = gtk_entry_new ();
    
        //get_stream_values();
        /* Retrieve the user's information for the default values. */
        s_val = (char *)ether_to_str(cur_pak_info.src_mac);
        gtk_entry_set_text (GTK_ENTRY (src_mac), s_val);
        free(s_val);
        s_val = (char *)ether_to_str(cur_pak_info.dst_mac);
        gtk_entry_set_text (GTK_ENTRY (dst_mac), s_val);
        free(s_val);
        s_val = (char *)ip_to_str((uint8_t *)&cur_pak_info.src_ip);
        gtk_entry_set_text (GTK_ENTRY (src_ip), s_val);
        free(s_val);
        s_val = (char *)ip_to_str((uint8_t *)&cur_pak_info.dst_ip);
        gtk_entry_set_text (GTK_ENTRY (dst_ip), s_val);
        free(s_val);

        table = gtk_table_new (4, 2, FALSE);

        gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl2, 0, 1, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl3, 0, 1, 2, 3);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl4, 0, 1, 3, 4);
        gtk_table_attach_defaults (GTK_TABLE (table), src_mac, 1, 2, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), dst_mac, 1, 2, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), src_ip, 1, 2, 2, 3);
        gtk_table_attach_defaults (GTK_TABLE (table), dst_ip, 1, 2, 3, 4);
        gtk_table_set_row_spacings (GTK_TABLE (table), 5);
        gtk_table_set_col_spacings (GTK_TABLE (table), 5);
        gtk_container_set_border_width (GTK_CONTAINER (table), 5);
        gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
        gtk_widget_show_all (dialog);

        /* Run the dialog and output the data if the user clicks the OK button. */
        result = gtk_dialog_run (GTK_DIALOG (dialog));
        if (result == GTK_RESPONSE_OK)
        {
                p_src_mac  =  gtk_entry_get_text (GTK_ENTRY (src_mac));
                p_dst_mac  =  gtk_entry_get_text (GTK_ENTRY (dst_mac));
                p_src_ip   =  gtk_entry_get_text (GTK_ENTRY (src_ip));
                p_dst_ip   =  gtk_entry_get_text (GTK_ENTRY (dst_ip));

                err_val = 0;
                for (i = 1; (fpak_curr_info = pak_list_get(i)) != NULL; i++) {
                        if (fpak_curr_info->mem_alloc == 0) {
                                fseek(p->rfile,fpak_curr_info->offset,0);
                                p->buffer = p->base;
                                pcap_offline_read(p,1);
                                fpak_curr_info->pak = p->buffer;
                                fpak_curr_info->pak_len = p->cap_len;
                        }
                        if(update_mac_ip(p_src_mac, p_dst_mac, p_src_ip, p_dst_ip)) {
                                if (fpak_curr_info->mem_alloc == 0) {
                                        fpak_curr_info->pak = malloc(p->cap_len);
                                        memcpy(fpak_curr_info->pak,p->buffer,p->cap_len);
					fpak_curr_info->mem_alloc = 1;
                                        fpak_curr_info->pak_len = p->cap_len;
                                }
                        } else {
				if (fpak_curr_info->mem_alloc == 0) {
                                	fpak_curr_info->pak = NULL;
				}
                        }
                        if (err_val != 0) {
                                error_val();
                                goto ip_mac_change_end;
                        }
                }
                pl_display_modified_iter();
	}
ip_mac_change_end:
        gtk_widget_destroy (dialog);
}

void
pl_view_popup_menu_del_pak (GtkWidget *menuitem, gpointer userdata)
{
  GtkTreeSelection *selection;
  GtkTreeModel     *model;
  GtkTreeIter       iter;


  /* This will only work in single or browse selection mode! */
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(pl_treeview));
  if (gtk_tree_selection_get_selected(selection, &model, &iter))
  {
    gint no;

    gtk_tree_model_get (model, &iter, 0, &no, -1);
    pak_list_del_node(no);
    pl_display_modified_iter();
  }

}

void
pl_view_popup_menu_dup_pak (GtkWidget *menuitem, gpointer userdata)
{
  GtkTreeSelection *selection;
  GtkTreeModel     *model;
  GtkTreeIter       iter;


  /* This will only work in single or browse selection mode! */
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(pl_treeview));
  if (gtk_tree_selection_get_selected(selection, &model, &iter))
  {
    gint no;
    gtk_tree_model_get (model, &iter, 0, &no, -1);
    pak_list_dup_node(no);
    pl_display_modified_iter();
  }

}

void
pl_view_popup_menu_add_mtag (GtkWidget *menuitem, gpointer userdata)
{
        GtkTreeSelection *selection;
        GtkTreeModel     *model;
        GtkTreeIter       iter;
        GtkWidget *dialog, *table, *label, *exp, *stack, *ttl;
        GtkWidget *lbl1, *lbl2, *lbl3, *lbl4;
        gint result;
        char *s_val;
        const gchar *p_label, *p_exp, *p_stack, *p_ttl;
        uint32_t i;
        uint16_t label_val = 10, exp_val = 0, stack_val = 1, ttl_val = 64;
        struct pak_file_info *fpak_info;

        dialog = gtk_dialog_new_with_buttons ("MPLS values", NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_STOCK_OK, GTK_RESPONSE_OK,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                NULL);

        gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
        /* Create four entries that will tell the user what data to enter. */
        lbl1 = gtk_label_new ("MPLS Label:");
        lbl2 = gtk_label_new ("MPLS Experimental Bits:");
        lbl3 = gtk_label_new ("MPLS Bottom Of Label Stack:");
        lbl4 = gtk_label_new ("MPLS TTL:");

        label    = gtk_entry_new ();
        exp      = gtk_entry_new ();
        stack    = gtk_entry_new ();
        ttl      = gtk_entry_new ();

        //get_stream_values();
        /* Retrieve the user's information for the default values. */
        gtk_entry_set_text (GTK_ENTRY (label), "10");
        gtk_entry_set_text (GTK_ENTRY (exp), "0");
        gtk_entry_set_text (GTK_ENTRY (stack), "1");
        gtk_entry_set_text (GTK_ENTRY (ttl), "64");

        table = gtk_table_new (4, 2, FALSE);

        gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl2, 0, 1, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl3, 0, 1, 2, 3);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl4, 0, 1, 3, 4);
        gtk_table_attach_defaults (GTK_TABLE (table), label, 1, 2, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), exp, 1, 2, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), stack, 1, 2, 2, 3);
        gtk_table_attach_defaults (GTK_TABLE (table), ttl, 1, 2, 3, 4);
        gtk_table_set_row_spacings (GTK_TABLE (table), 5);
        gtk_table_set_col_spacings (GTK_TABLE (table), 5);
        gtk_container_set_border_width (GTK_CONTAINER (table), 5);
        gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
        gtk_widget_show_all (dialog);

        /* Run the dialog and output the data if the user clicks the OK button. */
	result = gtk_dialog_run (GTK_DIALOG (dialog));
        if (result == GTK_RESPONSE_OK)
        {
                p_label     =  gtk_entry_get_text (GTK_ENTRY (label));
                p_exp       =  gtk_entry_get_text (GTK_ENTRY (exp));
                p_stack     =  gtk_entry_get_text (GTK_ENTRY (stack));
                p_ttl       =  gtk_entry_get_text (GTK_ENTRY (ttl));

                label_val = atoi(p_label);
                exp_val   = atoi(p_exp);
                stack_val = atoi(p_stack);
                ttl_val   = atoi(p_ttl);    

                err_val = 0;
                selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(pl_treeview));
                if (gtk_tree_selection_get_selected(selection, &model, &iter))
                {
                        gint no;
                        gtk_tree_model_get (model, &iter, 0, &no, -1);
                        fpak_info = pak_list_get(no);
			add_mtag(fpak_info, label_val, exp_val, stack_val, ttl_val);
                }
                pl_display_modified_iter();
        }
        gtk_widget_destroy (dialog);
}

void
pl_view_popup_menu_add_vtag (GtkWidget *menuitem, gpointer userdata)
{
        GtkTreeSelection *selection;
        GtkTreeModel     *model;
        GtkTreeIter       iter;
        GtkWidget *dialog, *table, *priority, *cfi, *id;
        GtkWidget *lbl1, *lbl2, *lbl3;
        gint result;
        char *s_val;
        const gchar *p_priority, *p_cfi, *p_id;
        uint32_t i;
        uint16_t priority_val = 0, cfi_val = 0, id_val = 100;
        struct pak_file_info *fpak_info;

        dialog = gtk_dialog_new_with_buttons ("VLAN values", NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_STOCK_OK, GTK_RESPONSE_OK,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                NULL);

        gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
        /* Create four entries that will tell the user what data to enter. */
        lbl1 = gtk_label_new ("Priority:");
        lbl2 = gtk_label_new ("CFI:");
        lbl3 = gtk_label_new ("VLAN ID:");

        priority   = gtk_entry_new ();
        cfi   = gtk_entry_new ();
        id    = gtk_entry_new ();

        //get_stream_values();
        /* Retrieve the user's information for the default values. */
        gtk_entry_set_text (GTK_ENTRY (priority), "0");
        gtk_entry_set_text (GTK_ENTRY (cfi), "0");
        gtk_entry_set_text (GTK_ENTRY (id), "100");

        table = gtk_table_new (3, 2, FALSE);

        gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl2, 0, 1, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), lbl3, 0, 1, 2, 3);
        gtk_table_attach_defaults (GTK_TABLE (table), priority, 1, 2, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), cfi, 1, 2, 1, 2);
        gtk_table_attach_defaults (GTK_TABLE (table), id, 1, 2, 2, 3);
        gtk_table_set_row_spacings (GTK_TABLE (table), 5);
        gtk_table_set_col_spacings (GTK_TABLE (table), 5);
        gtk_container_set_border_width (GTK_CONTAINER (table), 5);
        gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
        gtk_widget_show_all (dialog);

        result = gtk_dialog_run (GTK_DIALOG (dialog));
        if (result == GTK_RESPONSE_OK)
        {
                p_priority  =  gtk_entry_get_text (GTK_ENTRY (priority));
                p_cfi       =  gtk_entry_get_text (GTK_ENTRY (cfi));
                p_id        =  gtk_entry_get_text (GTK_ENTRY (id));

                priority_val = atoi(p_priority);
                cfi_val      = atoi(p_cfi);
                id_val       = atoi(p_id);

                err_val = 0;
                selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(pl_treeview));
                if (gtk_tree_selection_get_selected(selection, &model, &iter))
                {
                        gint no;
                        gtk_tree_model_get (model, &iter, 0, &no, -1);
                        fpak_info = pak_list_get(no);
                        add_vtag(fpak_info, priority_val, cfi_val, id_val);
                }

        }
        pl_display_modified_iter();
        gtk_widget_destroy (dialog);
}

void
pl_view_popup_menu_frag_pak (GtkWidget *menuitem, gpointer userdata)
{
	GtkTreeSelection *selection;
	GtkTreeModel     *model;
	GtkTreeIter       iter;
        GtkWidget *dialog, *table, *w_frag_size;
        GtkWidget *lbl1;
        gint result;
        gchar *p_frag_size, *f_val;
        uint16_t fsize = 8;
        struct pak_file_info *fpak_curr_next = NULL;

        dialog = gtk_dialog_new_with_buttons ("Fragment Options", NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_STOCK_OK, GTK_RESPONSE_OK,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                NULL);
        gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);

        lbl1 = gtk_label_new ("Fragment Size:");
        w_frag_size   = gtk_entry_new ();

        gtk_entry_set_text (GTK_ENTRY (w_frag_size), "8");

        table = gtk_table_new (1, 2, FALSE);

        gtk_table_attach_defaults (GTK_TABLE (table), lbl1, 0, 1, 0, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), w_frag_size, 1, 2, 0, 1);

        gtk_container_set_border_width (GTK_CONTAINER (table), 5);
        gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox), table);
        gtk_widget_show_all (dialog);

        result = gtk_dialog_run (GTK_DIALOG (dialog));
        if (result == GTK_RESPONSE_OK)
        {
                p_frag_size = (gchar *)gtk_entry_get_text (GTK_ENTRY (w_frag_size));
                fsize = atoi(p_frag_size);
                err_val = 0;
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(pl_treeview));
		if (gtk_tree_selection_get_selected(selection, &model, &iter))
		{
    			gint no;
			gtk_tree_model_get (model, &iter, 0, &no, -1);
                	fpak_curr_info = pak_list_get(no);
                        frag_pak(fpak_curr_info, fsize);
                }

        }
        pl_display_modified_iter();
        gtk_widget_destroy (dialog);

}

uint8_t
pl_popup_menu (GtkWidget *treeview, GdkEventButton *event, gpointer userdata)
{
    GtkWidget *menu, *stream_val, *ip_val, *del_val, *dup_val, *frag_val, *vtag_val;
    GtkWidget *mpls_val;

    if (p == NULL) {
	return;
    }
 
    menu = gtk_menu_new();
 
    stream_val = gtk_menu_item_new_with_label("Change Stream values");
    ip_val     = gtk_menu_item_new_with_label("Replace MAC, IP Addresses");
    del_val    = gtk_menu_item_new_with_label("Delete Packet");
    dup_val    = gtk_menu_item_new_with_label("Create Duplicate");
    frag_val   = gtk_menu_item_new_with_label("Fragment Packet");
    vtag_val   = gtk_menu_item_new_with_label("Add VLAN Tag");
    mpls_val   = gtk_menu_item_new_with_label("Add MPLS Tag (ipv4 only)");
 
    
    g_signal_connect(stream_val, "activate",
                     (GCallback) pl_view_popup_menu_stream_change, pl_treeview);
    g_signal_connect(ip_val, "activate",
                     (GCallback) pl_view_popup_menu_mac_ip_change, pl_treeview);
    g_signal_connect(del_val, "activate",
                     (GCallback) pl_view_popup_menu_del_pak, pl_treeview);
    g_signal_connect(dup_val, "activate",
                     (GCallback) pl_view_popup_menu_dup_pak, pl_treeview);
    g_signal_connect(frag_val, "activate",
                     (GCallback) pl_view_popup_menu_frag_pak, pl_treeview);
    g_signal_connect(vtag_val, "activate",
                     (GCallback) pl_view_popup_menu_add_vtag, pl_treeview);
    g_signal_connect(mpls_val, "activate",
                     (GCallback) pl_view_popup_menu_add_mtag, pl_treeview);

 
    if ((cur_pak_info.L4_proto == 0x11) || (cur_pak_info.L4_proto == 0x06) && (cur_pak_info.L3_proto == 0x0800)) {
    	gtk_menu_shell_append(GTK_MENU_SHELL(menu), stream_val);
    }
    if (cur_pak_info.L3_proto == 0x0800) {
    	gtk_menu_shell_append(GTK_MENU_SHELL(menu), ip_val);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), frag_val);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), mpls_val);
    }
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), del_val);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), dup_val);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), vtag_val);
 
    gtk_widget_show_all(menu);
 
    /* Note: event can be NULL here when called from view_onPopupMenu;
 *      *  gdk_event_get_time() accepts a NULL argument */
    gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
                   (event != NULL) ? event->button : 0,
                   gdk_event_get_time((GdkEvent*)event));
}
 
 
gboolean
pl_menu_signal (GtkWidget *treeview, GdkEventButton *event, gpointer userdata)
{
	if (event->type == GDK_BUTTON_PRESS  &&  event->button == 3)
	{
		pl_popup_menu(treeview, event, userdata);
	}
	return FALSE; /* we handled this and continue to next*/ 
}

void
pl_pak_reorder(GtkWidget *widget, GdkDragContext *context, guint time, gpointer user_data)
{
	GtkTreeSelection *selection;
	GtkTreeModel     *model;
	GtkTreePath *path = NULL;
	GtkTreeIter iter;
	char pakno[255];
	gint no = 1, pak_no_prev;
	struct pak_file_info *cur_node, *node1, *node2, *temp_node;

	itoa(fpak_curr_info->pak_no, pakno, 10);
	gtk_tree_model_get_iter_from_string (GTK_TREE_MODEL(pl_store), &iter, "0");
	do
	{
		pak_no_prev = no;
		gtk_tree_model_get (GTK_TREE_MODEL(pl_store), &iter, 0, &no, -1);
		if (fpak_curr_info->pak_no == no)
		{
			break;
		}
	} while (gtk_tree_model_iter_next (GTK_TREE_MODEL(pl_store), &iter));

	cur_node = pak_list_get(fpak_curr_info->pak_no);
	node2 = pak_list_get(pak_no_prev);
	
	if (fpak_curr_info->pak_no != 1) {
		node1 = pak_list_get(fpak_curr_info->pak_no - 1);
		node1->next = cur_node->next;
		if (node1->next != NULL) {
			node1->next->prev = node1;
		}
	} else {
		po_info->next = cur_node->next;
		po_info->next->prev = po_info;
	}

	cur_node->prev = node2;
	cur_node->next = node2->next;

	node2->next = cur_node;

		
	pl_display_modified_iter();
}

void create_packet_list_pane(void)
{

        pl_treeview = gtk_tree_view_new ();
	gtk_tree_view_set_reorderable(GTK_TREE_VIEW(pl_treeview), TRUE);
        setup_pl_tree_view (pl_treeview);
	g_object_set (G_OBJECT (pl_treeview), "enable-grid-lines", GTK_TREE_VIEW_GRID_LINES_HORIZONTAL, NULL);

        pl_store = gtk_tree_store_new (7, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

        gtk_tree_view_set_model (GTK_TREE_VIEW (pl_treeview), GTK_TREE_MODEL (pl_store));

        g_signal_connect (G_OBJECT (pl_treeview), "button-press-event",
                        (GCallback) pl_menu_signal, NULL);
	g_signal_connect (G_OBJECT (pl_treeview), "cursor-changed",
                      G_CALLBACK (pl_cur_changed), NULL);
	g_signal_connect(G_OBJECT (pl_treeview), "drag_end",
                    G_CALLBACK(pl_pak_reorder), pl_store);
 
	

        pl_scrolled_win = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_set_size_request(pl_scrolled_win, -1, 280);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (pl_scrolled_win),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_container_add (GTK_CONTAINER (pl_scrolled_win), pl_treeview);

}

void
create_main_vbox(void)
{
	mn_vbox = gtk_vbox_new (FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(mn_vbox), 1);
	gtk_container_add (GTK_CONTAINER (top_level), mn_vbox);
}

void
p_cur_changed(GtkTreeView *treeview)
{
	GtkTreeSelection *selection;
	GtkTreeModel     *model;
	GtkTreeIter       iter;

	gchar *name;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		gtk_tree_model_get (model, &iter, 0, &name, -1);
		gtk_tree_model_get (model, &iter, 2, &p_ref_proto, -1);
		gtk_tree_model_get (model, &iter, 3, &record_l1, -1);
		gtk_tree_model_get (model, &iter, 4, &record_l2, -1);
		strcpy(ptype,name);
	}
	g_free(name);
}
	
void
create_packet_display_pane()
{

	p_treeview = gtk_tree_view_new ();
	setup_p_tree_view(p_treeview);
	gtk_tree_view_set_rules_hint (GTK_TREE_VIEW(p_treeview), TRUE);
	p_store = gtk_tree_store_new (5, G_TYPE_STRING,G_TYPE_STRING,G_TYPE_INT,G_TYPE_INT,G_TYPE_INT);

	gtk_tree_view_set_model (GTK_TREE_VIEW (p_treeview), GTK_TREE_MODEL (p_store));
	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW (p_treeview), FALSE);
//	g_object_set (G_OBJECT (p_treeview), "hover-expand", TRUE, NULL);


        g_signal_connect (G_OBJECT (p_treeview), "cursor-changed",
                      G_CALLBACK (p_cur_changed), NULL);
	p_scrolled_win = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_set_size_request(p_scrolled_win, -1, 95);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (p_scrolled_win),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_container_add (GTK_CONTAINER (p_scrolled_win), p_treeview);
}

void
create_hex_display_pane()
{
	vpaned1 = gtk_vpaned_new ();
	vpaned2 = gtk_vpaned_new ();

	hex_textview = gtk_text_view_new ();
	gtk_text_view_set_justification (GTK_TEXT_VIEW (hex_textview), GTK_JUSTIFY_FILL);
	gtk_text_view_set_editable (GTK_TEXT_VIEW (hex_textview), TRUE);

	hex_buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (hex_textview));
	

	hex_scrolled_win = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_set_size_request(hex_scrolled_win, -1, 75);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (hex_scrolled_win),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (hex_scrolled_win), hex_textview);

	gtk_paned_add1 (GTK_PANED (vpaned1), pl_scrolled_win);
        gtk_paned_add2 (GTK_PANED (vpaned1), vpaned2);
        gtk_paned_pack1 (GTK_PANED (vpaned2), p_scrolled_win, TRUE, TRUE);
        gtk_paned_pack2 (GTK_PANED (vpaned2), hex_scrolled_win, FALSE, FALSE);

	gtk_container_add(GTK_CONTAINER(mn_vbox), vpaned1);
}

void 
send_pak() {
        gchar *string;
	uint32_t i;
	struct pak_file_info *fpak_temp;

	fpak_temp = fpak_curr_info;
        string = (gchar *)gtk_entry_get_text (GTK_ENTRY (GTK_COMBO (intf_combo)->entry));

	if (p == NULL) {
		goto send_pak_end;
	}
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (send_all_check))) {
               for (i = 1; (fpak_curr_info = pak_list_get(i)) != NULL; i++) {
                        if (fpak_curr_info->mem_alloc == 0) {
                                fseek(p->rfile,fpak_curr_info->offset,0);
                                p->buffer = p->base;
                                pcap_offline_read(p,1);
                        } else {
				p->buffer = fpak_curr_info->pak;
				p->cap_len = fpak_curr_info->pak_len;
			}
			SendPak(string,p->buffer, p->cap_len);
                }
	} else {
		SendPak(string,p->buffer, p->cap_len);
	}
send_pak_end:
	fpak_curr_info = fpak_temp;
}
void
create_tool_bar()
{
        GList *inf_list = NULL;
        GtkWidget *table, *send_button;
        char intf[20][10];
        int nifs, i;

        table = gtk_table_new (1, 3, FALSE);
	send_all_check = gtk_check_button_new_with_label ("Send All Packets");

        send_button = gtk_button_new_with_label("Send");
        intf_combo = gtk_combo_new();

        if (nifs = intf_list(intf)) {
                for (i = 0; i < nifs; i++) {
                        inf_list = g_list_append (inf_list, intf[i]);
                }
        }

        gtk_combo_set_popdown_strings (GTK_COMBO (intf_combo), inf_list);



        g_signal_connect (G_OBJECT (send_button), "clicked",
                        G_CALLBACK (send_pak), "Send");

        gtk_table_attach (GTK_TABLE (table), send_button, 0, 1, 0, 1,
                                GTK_SHRINK, GTK_SHRINK, 0, 0);

        gtk_table_attach (GTK_TABLE (table), intf_combo, 1, 2, 0, 1,
                                GTK_SHRINK, GTK_SHRINK, 0, 0);

        gtk_table_attach (GTK_TABLE (table), send_all_check, 2, 3, 0, 1,
                                GTK_SHRINK, GTK_SHRINK, 0, 0);

        gtk_box_pack_start (GTK_BOX (mn_vbox), table,FALSE,TRUE,0);

}

void
init_main_window()
{

	pak_list_init();
	
	create_top_window();

	create_main_vbox();	

	create_menubar();

	create_tool_bar();

	create_packet_list_pane();

	create_packet_display_pane();

	create_hex_display_pane();

	show_main_window();
}

main(int argc, char *argv[])
{

        gtk_init (&argc, &argv);
        init_main_window();
        return 0;
}
