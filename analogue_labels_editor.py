#!/usr/bin/env python3
"""
Analogue 3D Labels.db Editor
GUI tool for viewing and editing labels.db file

File format:
- 0x0000-0x00FF: Header
- 0x0100-0x40FF: Cartridge signature index (32-bit LE CRC32, sorted ascending, unused = 0xFFFFFFFF)
- 0x4100-EOF: Image data (74×86 pixels, 4 bytes/pixel BGRA, 25,600 bytes per image)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import os
from pathlib import Path
from PIL import Image, ImageTk
import io
from datetime import datetime

# Constants
HEADER_SIZE = 0x100
INDEX_START = 0x100
INDEX_END = 0x4100
IMAGE_START = 0x4100
IMAGE_SIZE = 25600  # 74 × 86 × 4 bytes
IMAGE_WIDTH = 74
IMAGE_HEIGHT = 86
UNUSED_ENTRY = 0xFFFFFFFF

class LabelsDBEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Analogue 3D Labels.db Editor")
        self.root.geometry("1200x800")
        
        self.labels_db_path = None
        self.labels_data = None
        self.header = None
        self.signatures = []  # List of CRC32 signatures
        self.images = {}  # Dict mapping CRC32 to PIL Image
        self.current_crc32 = None
        self.modified = False
        self.installed_signatures = set()  # Set of installed CRC32 signatures
        self.game_names = {}  # Dict mapping CRC32 to game name
        self.library_db_path = None
        self.library_data = None
        self.game_records = {}  # Dict mapping CRC32 to {play_time, date_added}
        
        self.setup_ui()
        self.auto_detect_labels_db()
    
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="Database File", padding="5")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="labels.db:").grid(row=0, column=0, padx=(0, 5))
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, state="readonly", width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(file_frame, text="Browse...", command=self.browse_labels_db).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(file_frame, text="Load", command=self.load_labels_db).grid(row=0, column=3)
        
        ttk.Label(file_frame, text="library.db:").grid(row=1, column=0, padx=(0, 5), pady=(5, 0))
        self.library_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.library_path_var, state="readonly", width=50).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(5, 0))
        ttk.Button(file_frame, text="Browse...", command=self.browse_library_db).grid(row=1, column=2, padx=(0, 5), pady=(5, 0))
        ttk.Button(file_frame, text="Load", command=self.load_library_db).grid(row=1, column=3, pady=(5, 0))
        
        # Left panel - Signature list
        left_frame = ttk.LabelFrame(main_frame, text="Cartridge Signatures", padding="5")
        left_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(1, weight=1)
        
        # Search box and filter
        search_frame = ttk.Frame(left_frame)
        search_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_signatures)
        ttk.Entry(search_frame, textvariable=self.search_var).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        
        # Only show installed checkbox
        self.only_installed_var = tk.BooleanVar()
        self.only_installed_var.trace('w', self.filter_signatures)
        ttk.Checkbutton(search_frame, text="Only show installed", variable=self.only_installed_var).grid(row=0, column=2)
        
        # Signature listbox with scrollbar
        list_frame = ttk.Frame(left_frame)
        list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.signature_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=("Courier", 9))
        self.signature_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.signature_listbox.bind('<<ListboxSelect>>', self.on_signature_select)
        scrollbar.config(command=self.signature_listbox.yview)
        
        self.entry_count_label = ttk.Label(left_frame, text="Total: 0 entries")
        self.entry_count_label.grid(row=2, column=0, pady=(5, 0))
        
        # Right panel - Image viewer and editor
        right_frame = ttk.LabelFrame(main_frame, text="Image Editor", padding="5")
        right_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        right_frame.columnconfigure(0, weight=1)
        
        # CRC32 info
        info_frame = ttk.Frame(right_frame)
        info_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        info_frame.columnconfigure(1, weight=1)
        
        ttk.Label(info_frame, text="CRC32:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.crc32_var = tk.StringVar(value="No selection")
        ttk.Label(info_frame, textvariable=self.crc32_var, font=("Courier", 10)).grid(row=0, column=1, sticky=tk.W)
        
        # Library.db data display
        library_info_frame = ttk.LabelFrame(info_frame, text="Library Data", padding="5")
        library_info_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        library_info_frame.columnconfigure(1, weight=1)
        
        ttk.Label(library_info_frame, text="Play Time:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.play_time_var = tk.StringVar(value="N/A")
        ttk.Label(library_info_frame, textvariable=self.play_time_var).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(library_info_frame, text="Date Added:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.date_added_var = tk.StringVar(value="N/A")
        ttk.Label(library_info_frame, textvariable=self.date_added_var).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # Image display
        image_frame = ttk.Frame(right_frame)
        image_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.image_label = ttk.Label(image_frame, text="No image loaded", anchor=tk.CENTER, background="gray90")
        self.image_label.pack()
        
        # Image controls
        controls_frame = ttk.Frame(right_frame)
        controls_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(controls_frame, text="Replace Image", command=self.replace_image).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(controls_frame, text="Export Image", command=self.export_current_image).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(controls_frame, text="Export All Images", command=self.export_all_images).grid(row=0, column=2)
        
        # Save button
        save_frame = ttk.Frame(right_frame)
        save_frame.grid(row=3, column=0, sticky=(tk.W, tk.E))
        
        self.save_button = ttk.Button(save_frame, text="Save Modified labels.db", command=self.save_labels_db, style="Accent.TButton")
        self.save_button.pack(fill=tk.X)
        
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=2)
        main_frame.rowconfigure(1, weight=1)
    
    def auto_detect_labels_db(self):
        """Auto-detect labels.db in current directory or common locations"""
        current_dir = Path.cwd()
        possible_paths = [
            current_dir / "labels.db",
            current_dir / "Library" / "N64" / "Images" / "labels.db",
            current_dir / "root" / "Library" / "N64" / "Images" / "labels.db",
        ]
        
        for path in possible_paths:
            if path.exists():
                self.file_path_var.set(str(path))
                self.labels_db_path = str(path)
                self.load_labels_db()
                # Also try to auto-detect library.db
                self.auto_detect_library_db()
                return
    
    def auto_detect_library_db(self):
        """Auto-detect library.db in common locations"""
        if not self.labels_db_path:
            return
        
        labels_dir = Path(self.labels_db_path).parent
        possible_paths = [
            labels_dir.parent / "library.db",  # Library/N64/library.db
            labels_dir.parent.parent / "library.db",  # Library/library.db
            Path.cwd() / "Library" / "N64" / "library.db",
            Path.cwd() / "library.db",
        ]
        
        for path in possible_paths:
            if path.exists():
                self.library_path_var.set(str(path))
                self.library_db_path = str(path)
                self.load_library_db()
                return
    
    def browse_library_db(self):
        """Browse for library.db file"""
        path = filedialog.askopenfilename(
            title="Select library.db",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        if path:
            self.library_path_var.set(path)
            self.library_db_path = path
    
    def load_library_db(self):
        """Load library.db and parse game records"""
        path = self.library_path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Please select a valid library.db file")
            return
        
        try:
            with open(path, 'rb') as f:
                self.library_data = f.read()
            
            self.library_db_path = path
            self.parse_library_db()
            messagebox.showinfo("Success", f"Loaded library.db\nSize: {len(self.library_data):,} bytes\nRecords: {len(self.game_records)}")
            # Update display if a signature is selected
            if self.current_crc32:
                self.update_library_info(self.current_crc32)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load library.db:\n{str(e)}")
    
    def parse_library_db(self):
        """Parse library.db structure"""
        if len(self.library_data) < 0x4100:
            raise ValueError("File too small")
        
        # library.db structure:
        # 0x0000-0x00FF: Header
        # 0x0100-0x011F: Hash index (8 slots, 4 bytes each, little-endian)
        # 0x0200-0x40FF: Reserved/Padding
        # 0x4100+: Game records (12 bytes each: date_added, play_time, unknown)
        
        self.game_records = {}
        
        # Read hash index
        hash_index = []
        for i in range(0x100, 0x120, 4):
            if i + 4 <= len(self.library_data):
                hash_val = struct.unpack('<I', self.library_data[i:i+4])[0]
                if hash_val != 0 and hash_val != 0xFFFFFFFF:
                    hash_index.append(hash_val)
        
        # Read game records
        record_size = 12
        record_start = 0x4100
        
        for idx, hash_val in enumerate(hash_index):
            record_offset = record_start + (idx * record_size)
            if record_offset + record_size <= len(self.library_data):
                record_data = self.library_data[record_offset:record_offset + record_size]
                
                # Parse record: date_added (4), play_time (4), unknown (4)
                date_added = struct.unpack('<I', record_data[0:4])[0]
                play_time = struct.unpack('<I', record_data[4:8])[0]
                unknown = struct.unpack('<I', record_data[8:12])[0]
                
                self.game_records[hash_val] = {
                    'date_added': date_added,
                    'play_time': play_time,
                    'unknown': unknown
                }
    
    def format_play_time(self, seconds):
        """Format play time in seconds to human-readable format"""
        if seconds == 0:
            return "0 seconds"
        
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        parts = []
        if hours > 0:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes > 0:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        if secs > 0 or not parts:
            parts.append(f"{secs} second{'s' if secs != 1 else ''}")
        
        return ", ".join(parts)
    
    def format_date_added(self, timestamp):
        """Format date added timestamp"""
        if timestamp == 0:
            return "Unknown"
        
        # Try to interpret as Unix timestamp
        try:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            # If not a valid Unix timestamp, show as ID
            return f"ID: {timestamp}"
    
    def update_library_info(self, crc32):
        """Update library info display for selected CRC32"""
        if crc32 in self.game_records:
            record = self.game_records[crc32]
            self.play_time_var.set(self.format_play_time(record['play_time']))
            self.date_added_var.set(self.format_date_added(record['date_added']))
        else:
            self.play_time_var.set("Not in library.db")
            self.date_added_var.set("Not in library.db")
    
    def browse_labels_db(self):
        """Browse for labels.db file"""
        path = filedialog.askopenfilename(
            title="Select labels.db",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        if path:
            self.file_path_var.set(path)
            self.labels_db_path = path
    
    def load_labels_db(self):
        """Load labels.db and parse structure"""
        path = self.file_path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Please select a valid labels.db file")
            return
        
        try:
            with open(path, 'rb') as f:
                self.labels_data = f.read()
            
            self.labels_db_path = path
            self.parse_labels_db()
            self.scan_installed_games()
            self.populate_signature_list()
            self.modified = False
            messagebox.showinfo("Success", f"Loaded labels.db\nSize: {len(self.labels_data):,} bytes\nSignatures: {len(self.signatures)}\nInstalled: {len(self.installed_signatures)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load labels.db:\n{str(e)}")
    
    def parse_labels_db(self):
        """Parse labels.db structure"""
        if len(self.labels_data) < IMAGE_START:
            raise ValueError("File too small")
        
        # Read header
        self.header = self.labels_data[0:HEADER_SIZE]
        
        # Read signature index
        self.signatures = []
        index_data = self.labels_data[INDEX_START:INDEX_END]
        
        for i in range(0, len(index_data), 4):
            signature = struct.unpack('<I', index_data[i:i+4])[0]
            if signature == UNUSED_ENTRY:
                break
            self.signatures.append(signature)
        
        # Load images
        self.images = {}
        for idx, signature in enumerate(self.signatures):
            image_offset = IMAGE_START + (idx * IMAGE_SIZE)
            if image_offset + IMAGE_SIZE <= len(self.labels_data):
                image_data = self.labels_data[image_offset:image_offset + IMAGE_SIZE]
                img = self.decode_bgra_image(image_data)
                if img:
                    self.images[signature] = img
    
    def decode_bgra_image(self, bgra_data):
        """Decode BGRA pixel data to PIL Image"""
        if len(bgra_data) < IMAGE_WIDTH * IMAGE_HEIGHT * 4:
            return None
        
        # Create image from BGRA data
        img = Image.frombytes('RGBA', (IMAGE_WIDTH, IMAGE_HEIGHT), bgra_data, 'raw', 'BGRA')
        return img
    
    def encode_bgra_image(self, img):
        """Encode PIL Image to BGRA pixel data"""
        # Ensure correct size
        if img.size != (IMAGE_WIDTH, IMAGE_HEIGHT):
            img = img.resize((IMAGE_WIDTH, IMAGE_HEIGHT), Image.Resampling.LANCZOS)
        
        # Convert to RGBA if needed
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        # Get pixel data
        rgba_data = img.tobytes('raw', 'RGBA')
        
        # Convert RGBA to BGRA
        bgra_data = bytearray(IMAGE_SIZE)
        for i in range(0, IMAGE_WIDTH * IMAGE_HEIGHT * 4, 4):
            r = rgba_data[i]
            g = rgba_data[i + 1]
            b = rgba_data[i + 2]
            a = rgba_data[i + 3]
            
            bgra_data[i] = b
            bgra_data[i + 1] = g
            bgra_data[i + 2] = r
            bgra_data[i + 3] = a
        
        # Pad to IMAGE_SIZE
        return bytes(bgra_data)
    
    def scan_installed_games(self):
        """Scan Library/N64/Games directory for installed games"""
        self.installed_signatures = set()
        self.game_names = {}
        
        if not self.labels_db_path:
            return
        
        # Try to find Games directory relative to labels.db
        labels_dir = Path(self.labels_db_path).parent
        possible_games_dirs = [
            labels_dir.parent.parent / "Games",  # Library/N64/Games
            labels_dir.parent / "Games",  # N64/Games
            Path.cwd() / "Library" / "N64" / "Games",
            Path.cwd() / "Games",
        ]
        
        games_dir = None
        for path in possible_games_dirs:
            if path.exists() and path.is_dir():
                games_dir = path
                break
        
        if not games_dir:
            return
        
        # Scan for game folders
        try:
            import re
            for item in games_dir.iterdir():
                if item.is_dir():
                    folder_name = item.name
                    game_name = None
                    sig = None
                    
                    # Extract signature and game name from folder name
                    # Format: [game name]+[signature] or [game name] [signature]
                    # Signature can be: 0x0a00b94f, 0a00b94f, or just hex digits
                    
                    # Pattern 1: +0x followed by 8 hex digits
                    match = re.search(r'^(.+?)\+0x([0-9a-fA-F]{8})$', folder_name)
                    if match:
                        try:
                            game_name = match.group(1).strip()
                            sig = int(match.group(2), 16)
                            self.installed_signatures.add(sig)
                            self.game_names[sig] = game_name
                            continue
                        except:
                            pass
                    
                    # Pattern 2: + followed by 8 hex digits
                    match = re.search(r'^(.+?)\+([0-9a-fA-F]{8})$', folder_name)
                    if match:
                        try:
                            game_name = match.group(1).strip()
                            sig = int(match.group(2), 16)
                            self.installed_signatures.add(sig)
                            self.game_names[sig] = game_name
                            continue
                        except:
                            pass
                    
                    # Pattern 3: Space followed by 0x and 8 hex digits
                    match = re.search(r'^(.+?) 0x([0-9a-fA-F]{8})$', folder_name)
                    if match:
                        try:
                            game_name = match.group(1).strip()
                            sig = int(match.group(2), 16)
                            self.installed_signatures.add(sig)
                            self.game_names[sig] = game_name
                            continue
                        except:
                            pass
                    
                    # Pattern 4: Space followed by 8 hex digits
                    match = re.search(r'^(.+?) ([0-9a-fA-F]{8})$', folder_name)
                    if match:
                        try:
                            game_name = match.group(1).strip()
                            sig = int(match.group(2), 16)
                            self.installed_signatures.add(sig)
                            self.game_names[sig] = game_name
                            continue
                        except:
                            pass
        except Exception as e:
            print(f"Error scanning games directory: {e}")
    
    def populate_signature_list(self):
        """Populate the signature listbox"""
        self.filter_signatures()
    
    def filter_signatures(self, *args):
        """Filter signature list based on search and installed filter"""
        self.signature_listbox.delete(0, tk.END)
        
        # Start with all signatures
        filtered = self.signatures.copy()
        
        # Apply "only installed" filter
        if self.only_installed_var.get():
            filtered = [sig for sig in filtered if sig in self.installed_signatures]
        
        # Apply search filter
        search_term = self.search_var.get().lower()
        if search_term:
            filtered = [sig for sig in filtered if search_term in f"0x{sig:08x}".lower()]
        
        self.filtered_signatures = filtered
        
        for sig in self.filtered_signatures:
            # Show game name if available
            if sig in self.game_names:
                display = f"0x{sig:08x} - {self.game_names[sig]}"
            else:
                display = f"0x{sig:08x}"
            self.signature_listbox.insert(tk.END, display)
        
        total = len(self.signatures)
        shown = len(self.filtered_signatures)
        installed = len(self.installed_signatures)
        
        if self.only_installed_var.get():
            self.entry_count_label.config(text=f"Showing: {shown} of {total} entries ({installed} installed)")
        else:
            self.entry_count_label.config(text=f"Total: {total} entries ({installed} installed)")
    
    def on_signature_select(self, event):
        """Handle signature selection"""
        selection = self.signature_listbox.curselection()
        if not selection:
            return
        
        idx = selection[0]
        crc32 = self.filtered_signatures[idx]
        self.current_crc32 = crc32
        
        self.crc32_var.set(f"0x{crc32:08x}")
        
        # Update library info
        self.update_library_info(crc32)
        
        # Display image
        if crc32 in self.images:
            img = self.images[crc32]
            # Scale up for display (4x for better visibility)
            display_img = img.resize((IMAGE_WIDTH * 4, IMAGE_HEIGHT * 4), Image.Resampling.NEAREST)
            photo = ImageTk.PhotoImage(display_img)
            self.image_label.config(image=photo, text='')
            self.image_label.image = photo  # Keep a reference
        else:
            self.image_label.config(image='', text="Image not found")
    
    def replace_image(self):
        """Replace image for current signature"""
        if not self.current_crc32:
            messagebox.showwarning("Warning", "Please select a signature first")
            return
        
        # Ask for image file
        file_path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            # Load and convert image
            img = Image.open(file_path)
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Update image
            self.images[self.current_crc32] = img
            self.modified = True
            
            # Refresh display
            self.on_signature_select(None)
            
            messagebox.showinfo("Success", "Image replaced. Don't forget to save!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image:\n{str(e)}")
    
    def export_current_image(self):
        """Export current image to file"""
        if not self.current_crc32 or self.current_crc32 not in self.images:
            messagebox.showwarning("Warning", "Please select a signature with an image")
            return
        
        default_name = f"image_{self.current_crc32:08x}.png"
        file_path = filedialog.asksaveasfilename(
            title="Save Image",
            defaultextension=".png",
            initialfile=default_name,
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                self.images[self.current_crc32].save(file_path, "PNG")
                messagebox.showinfo("Success", f"Image saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save image:\n{str(e)}")
    
    def export_all_images(self):
        """Export all images to a directory"""
        if not self.signatures:
            messagebox.showwarning("Warning", "No signatures loaded")
            return
        
        export_dir = filedialog.askdirectory(title="Select Export Directory")
        if not export_dir:
            return
        
        try:
            exported = 0
            for sig in self.signatures:
                if sig in self.images:
                    file_path = os.path.join(export_dir, f"image_{sig:08x}.png")
                    self.images[sig].save(file_path, "PNG")
                    exported += 1
            
            messagebox.showinfo("Success", f"Exported {exported} images to:\n{export_dir}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export images:\n{str(e)}")
    
    def save_labels_db(self):
        """Save modified labels.db"""
        if not self.labels_db_path:
            messagebox.showwarning("Warning", "No database loaded")
            return
        
        if not self.modified:
            messagebox.showinfo("Info", "No changes to save")
            return
        
        # Ask for save location
        save_path = filedialog.asksaveasfilename(
            title="Save labels.db",
            defaultextension=".db",
            initialfile=os.path.basename(self.labels_db_path),
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        
        if not save_path:
            return
        
        try:
            # Sort signatures
            sorted_signatures = sorted(self.signatures)
            
            # Build new file
            new_data = bytearray()
            
            # Write header
            new_data.extend(self.header)
            
            # Write signature index
            index_data = bytearray(INDEX_END - INDEX_START)
            for i, sig in enumerate(sorted_signatures):
                struct.pack_into('<I', index_data, i * 4, sig)
            # Fill rest with 0xFFFFFFFF
            for i in range(len(sorted_signatures), (INDEX_END - INDEX_START) // 4):
                struct.pack_into('<I', index_data, i * 4, UNUSED_ENTRY)
            new_data.extend(index_data)
            
            # Write images in sorted order
            for sig in sorted_signatures:
                if sig in self.images:
                    bgra_data = self.encode_bgra_image(self.images[sig])
                    new_data.extend(bgra_data)
                else:
                    # Pad with zeros if image missing
                    new_data.extend(b'\x00' * IMAGE_SIZE)
            
            # Write to file
            with open(save_path, 'wb') as f:
                f.write(new_data)
            
            self.modified = False
            messagebox.showinfo("Success", f"Saved labels.db to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save labels.db:\n{str(e)}")

def main():
    root = tk.Tk()
    app = LabelsDBEditor(root)
    root.mainloop()

if __name__ == '__main__':
    main()
