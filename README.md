# Analogue 3D Labels.db Editor
based on findings by http://a3d-tools.christopher-matthes.de/

A GUI tool for viewing and editing the `labels.db` file from your Analogue 3D console.

## Features

- **Load labels.db** - Browse or auto-detect the database file
- **View Signatures** - See all cartridge CRC32 signatures
- **View Images** - Display 74×86 pixel game label images
- **Replace Images** - Replace any game's label image
- **Export Images** - Export individual or all images as PNG
- **Save Database** - Save modified labels.db with sorted signatures

## File Format

- **0x0000-0x00FF**: Header
- **0x0100-0x40FF**: Cartridge signature index (32-bit LE CRC32, sorted ascending, unused = 0xFFFFFFFF)
- **0x4100-EOF**: Image data (74×86 pixels, 4 bytes/pixel BGRA, 25,600 bytes per image)

## Installation

1. Copy `analogue_labels_editor.py` to the root of your SD card
2. Make sure you have Python 3 with tkinter and Pillow installed

### Dependencies

```bash
# On Linux
sudo apt-get install python3-tk python3-pil

# On macOS
brew install python3-tk
pip install Pillow

# On Windows
pip install Pillow
# tkinter usually comes with Python
```

## Usage

### Linux/macOS

```bash
python3 analogue_labels_editor.py
```

### Windows

```cmd
python analogue_labels_editor.py
```

## How It Works

1. **Auto-Detection**: Automatically looks for `labels.db` in:
   - Current directory
   - `Library/N64/Images/labels.db`
   - `root/Library/N64/Images/labels.db`

2. **Parsing**: 
   - Reads header (0x0000-0x00FF)
   - Extracts CRC32 signatures from index (0x0100-0x40FF)
   - Loads BGRA image data (74×86 pixels, 25,600 bytes each)

3. **Editing**:
   - Replace images by selecting a signature and choosing a new image file
   - Images are automatically resized to 74×86 pixels
   - Changes are saved when you click "Save Modified labels.db"

4. **Saving**:
   - Signatures are sorted in ascending order
   - Images are written in the same order as signatures
   - Index is rewritten with sorted signatures followed by 0xFFFFFFFF padding

## Image Format

- **Size**: 74×86 pixels (fixed)
- **Format**: BGRA (Blue, Green, Red, Alpha) - 4 bytes per pixel
- **Total Size**: 25,600 bytes per image
- **Display**: Images are shown at 4x scale (296×344) for better visibility

## Notes

- The tool automatically converts images to RGBA and resizes to 74×86 when replacing
- Always make a backup of your `labels.db` before editing
- The signature index must be sorted in ascending order for the console to read it correctly

---

**Status**: Fully functional - can view, edit, and save labels.db files.

