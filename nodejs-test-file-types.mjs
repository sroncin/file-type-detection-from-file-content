import * as fs from 'fs';
import path from 'path';

/**
 * detects file type by file header bytes
 * @param {String} filePath - complete path to file
 * @returns {String|null} file type or null if not found
 * @see @link{https://www.garykessler.net/library/file_sigs.html}
 * @see @link{https://en.wikipedia.org/wiki/List_of_file_signatures}
 */
function getFileType(filePath) {
    if (!filePath || !fs.statSync(filePath).isFile()) {
        return null;
    }

    const buffer = fs.readFileSync(filePath);
    const hexSignature = buffer.subarray(0, 16).toString('hex').toUpperCase();

    // Special handling cases first (more specific checks)
    const specialHandlers = {
        'D0CF11E0A1B11AE1': () => {
            const content = buffer.toString('hex').toUpperCase();
            if (content.includes('57006F0072006B0062006F006F006B')) return 'xls';
            if (content.includes('57006F00720064002E0044006F00630075006D0065006E0074')) return 'doc';
            if (content.includes('500072006500730065006E007400610074006900')) return 'ppt';
            return 'ole';
        },
        '504B': () => {
            try {
                const content = buffer.toString('hex').toUpperCase();
                if (content.includes('776F72642F')) return 'docx';
                if (content.includes('786C2F')) return 'xlsx';
                if (content.includes('7070742F')) return 'pptx';
                if (content.includes('4D4554412D494E462F')) return 'jar';
                if (content.includes('416E64726F69644D616E69666573742E786D6C')) return 'apk';
                return 'zip';
            } catch {
                return 'zip';
            }
        },
        '52494646': () => {
            const format = buffer.subarray(8, 12).toString('hex').toUpperCase();
            if (format === '57415645') return 'wav';
            if (format === '41564920') return 'avi';
            return null;
        },
        'FFD8FF': () => {
            const jpegMarker = hexSignature.substring(6, 8);
            const jpegTypes = {
                'E0': 'jpg',
                'E1': 'jpeg',
                'E2': 'jpe',
                'E3': 'jpeg',
                'E8': 'jpg',
                'DB': 'jpg',
                'EE': 'jpg'
            };
            return jpegTypes[jpegMarker] || 'jpg';
        },
        '4D5A': () => {
            const content = buffer.toString('hex').toUpperCase();
            if (content.includes('504500004C')) return 'dll';
            if (content.includes('50450000')) return 'exe';
            return 'exe';
        },
        '3C3F786D6C': () => {
            const content = buffer.toString('hex').toUpperCase();
            return content.includes('3C737667') ? 'svg' : 'xml';
        },
        '3C21': () => {
            const content = buffer.toString('hex').toUpperCase();
            if (content.startsWith('3C21444F43')) return 'html';  // <!DOC
            if (content.includes('444F43545950452068746D6C')) return 'html';
            if (content.includes('3C3F786D6C')) return 'xml';
            return 'html';
        }
    };

    // Check special handlers first
    for (const [signature, handler] of Object.entries(specialHandlers)) {
        if (hexSignature.startsWith(signature)) {
            const result = handler();
            if (result) return result;
        }
    }

    const signatures = {
        // Images
        '89504E470D0A1A0A': 'png',
        '47494638': 'gif',
        '49492A00': 'tiff', //tif/tiff = Intel byte ordering (little-endian)
        '4D4D002A': 'tiff', //tif/tiff = Motorola byte ordering (big-endian)
        '424D': 'bmp',
        '414F4C494458': 'idx',

        // JPEG2000 signatures
        '0000000C6A502020': 'jp2',  // Standard JPEG2000
        '0000000C6A5020200D0A': 'jp2',  // Alternative signature
        'FF4FFF51': 'jp2',          // JPEG2000 Codestream

        // Add ICO/CUR file signature
        '00000100': 'ico',
        '00000200': 'cur',

        // SVG and other (XML-based) image formats
        '3C737667': 'svg', //represents "<svg" - when the SVG starts directly with the SVG tag
        '38425053': 'psd',
        '252150532D': 'eps', //represents "%!PS-" - Standard EPS files starting with
        'C5D0D3C6': 'eps', //Binary EPS files with a binary header
        '4949524F4D': 'cin', //Cineon image format with Intel byte ordering
        '802A5FD7': 'cin', //Cineon image format with alternative header structure
        '53445058': 'dpx',
        '464C4946': 'flif',
        '0061736D': 'wasm',

        // Audio/Video
        '494433': 'mp3', //represents "ID3" - MP3 files with ID3 tags
        'FFFB': 'mp3', //MPEG-1 Layer 3 or MPEG-2 Layer 3 file
        'FFF3': 'mp3', //MPEG-1 Layer 3 file
        'FFF2': 'mp3', //MPEG-2 Layer 3 file
        '4F676753': 'oga',
        '4F67675300020000': 'ogg',
        '664C6143': 'flac',
        '1A45DFA3': 'mkv', //mkv/webm
        '000001BA': 'mpg', //mpg/mpeg = MPEG Program Stream
        '000001B3': 'mpg', //mpg/mpeg = MPEG Sequence Header
        '2321414D52': 'amr', //for AMR (Adaptive Multi-Rate) audio files
        '4D546864': 'mid',
        '4D5468640000000600': 'midi',
        '1F43': 'mod',
        '4F70757348656164': 'opus',
        '2E736E64': 'au',
        '464F524D00': 'aiff',

        // Archives & Compression
        '526172211A0700': 'rar',
        '377ABCAF271C': '7z',
        '1F8B': 'tgz', //For TAR GZ compressed files
        '1F8B08': 'gz', //For GZ compressed files
        '425A68': 'bz2',
        '1F9D': 'z',
        '1FA0': 'z',
        '4C5A4950': 'lzip',
        '4C5A4F': 'lzo',
        '535A444488': 'xz',
        '5D00': 'lzma',
        '28B52FFD': 'zst',

        // Documents
        '7B5C72746631': 'rtf',
        '0D444F43': 'doc',
        '435753': 'swf',
        '465753': 'swf',
        '1D7D': 'tex',
        '7573746172003030': 'tar', //represents "ustar\0\0" - GNU TAR format
        '7573746172202000': 'tar', //represents "ustar \0" - POSIX/UNIX TAR format

        // Executables & Libraries
        '7F454C46': 'elf',
        'CAFEBABE': 'class',
        'FEEDFACE': 'macho',
        'FEEDFACF': 'macho64',
        'CEFAEDFE': 'macho_be',
        'CFFAEDFE': 'macho64_be',
        'DEY\0': 'dey',
        'CAF1': 'lu',

        // Database & System
        '53514C69746520': 'sqlite',
        '4D5346532000': 'msfs',
        '504D4F43434D4F43': 'pmoccmoc',

        // Web & Programming
        '3C68746D6C': 'html', //represents "<html" - HTML files starting directly with html tag
        '3C484541443E': 'html', //represents "" - HTML files starting with head tag
        '2F2A2058504D202A2F': 'xpm',

        // Adobe
        '255044462D': 'pdf', //represents "%PDF-"

        // Mail
        '44656C69766572792D646174653A': 'email', //represents "Delivery-date:" header
        '46726F6D3A20': 'email', //represents "From: " header
        '52657475726E2D506174683A': 'email', //represents "Return-Path:" header
        '582D': 'email', //represents "X-" custom header prefix
        '4D6573736167652D4944': 'email',    // Message-ID
        '52656365697665643A': 'email',      // Received:
        '446174653A': 'email',              // Date:
        '546F3A': 'email',                  // To:
        '5375626A6563743A': 'email',        // Subject:
        '4D494D452D56657273696F6E': 'email', // MIME-Version

        // Crypto
        '2D2D2D2D2D424547494E': 'pem',
        '5361746F7368693A': 'bitcoin',

        // 3D/CAD Files
        '534F4C4944': 'stl',    // STL (STereoLithography) files
        '23204D6174': 'obj',    // Wavefront 3D Object File
        '4D4D4D4D': 'max',      // 3DS Max File
        '43415431': 'dwg',      // AutoCAD Drawing Database

        // Font Files
        '00010000': 'ttf',      // TrueType Font
        '4F54544F': 'otf',      // OpenType Font
        '774F4646': 'woff',     // Web Open Font Format
        '774F4632': 'woff2',    // Web Open Font Format 2.0

        // Scientific/Technical
        '0E574B53': 'wks',      // Workspace File
        '4E434831': 'nch',      // LabChart File
        '53494D504C45': 'fits', // Flexible Image Transport System - represents "SIMPLE" - the mandatory keyword that starts all FITS files.

        // Game Files
        '44445320': 'dds',      // DirectDraw Surface
        '4E45531A': 'nes',      // Nintendo ROM
        '8001': 'sfc',          // Super Nintendo ROM

        // Virtual Machine
        '4B444D56': 'vmdk',     // VMware Disk File
        '3C3C3C20': 'vbox',     // VirtualBox Config File

        // Configuration
        '5B676C6F': 'ini',      // Windows INI file
        '7B0A': 'json',         // JSON file
        '2D2D2D2D2D': 'yaml',       // YAML file -- must be after pem signature !

        // Others
        '4C000000011402': 'lnk',
        '0000001466747970': 'mov', //mov/qt - MOV with a specific atom size of 0x14
        '0000001866747970': 'mov', //mov/qt - MOV with a specific atom size of 0x18
        '49536328': 'cab',
        '4C5646': 'lvf',
        '4D444D5093A7': 'mdmp',
        '504147454455': 'pagedup',
        '213C617263683E': 'deb',
        '4344303031': 'iso',
        '00014244': 'dba',
        '00014454': 'tda', //Telegram Desktop Application data files
        '0002': 'tda', //Telegram Desktop Application data files
        '0003': 'tda', //Telegram Desktop Application data files
        '0004': 'tda' //Telegram Desktop Application data files
    };

    // Check binary signatures
    for (const [signature, fileType] of Object.entries(signatures)) {
        if (hexSignature.startsWith(signature)) {
            return fileType;
        }
    }

    // Text file detection
    const sampleSize = Math.min(buffer.length, 1024);
    let printableChars = 0;
    
    for (let i = 0; i < sampleSize; i++) {
        const byte = buffer[i];
        if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
            printableChars++;
        }
    }

    if (printableChars / sampleSize > 0.9) {
        return 'txt';
    }

    return 'unknown';
}



// ***** MAIN *****
let localFilePath = "./assets/";
const userPath = process.argv[2];
if (userPath &&  fs.existsSync(userPath)) {
    localFilePath = userPath;
}
console.log(`List files from: ${localFilePath}`);

const files = fs.readdirSync(localFilePath);
files.forEach(file => {
    const fullPath = path.join(localFilePath, file);
    if (fs.statSync(fullPath).isFile()) {
        const fileType = getFileType(fullPath);
        console.log(`File: ${file} >> REAL Type: ${fileType}`);
    }
});


