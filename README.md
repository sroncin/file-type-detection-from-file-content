# File Type Detection

This project provides a Node.js utility for detecting the true file type of a file based on its binary content, rather than relying solely on file extensions.

## Prerequisites

- Node.js v16.0.0 or higher (LTS recommended)
- npm v6.0.0 or higher (comes bundled with Node.js)

## Installation

1. Create a new directory for the project:

   ```bash
   mkdir "file-type-detection-from-file-content"
   ```

2. Navigate to the project directory:

   ```bash
   cd "file-type-detection-from-file-content"
   ```

3. Clone the repository:

   ```bash
   git clone "https://github.com/sroncin/file-type-detection-from-file-content.git" .
    ```

4. Install dependencies:

   ```ps
   npm install
   ```

## Usage

Detect file types within a specified directory:

```ps
npm run start "path-to-the-folder-with-files"
```

The `<path_to_directory>` argument is optional. If omitted, the utility defaults to scanning the `./assets/` directory.

```ps
npm start ./my_files
```

## Project Maintenance

### Updating Dependencies

To update project dependencies to their latest versions:

```ps
npm update
```

### Cleaning the Project

To remove installed dependencies and lockfiles (useful for troubleshooting or ensuring a clean build):

```ps
npm ci
```

## Output

The utility outputs a list of files in the specified directory along with their detected true file types. The output format is as follows:

```ps
List files from: [specified_directory]
File: [filename] >> REAL Type: [detected_file_type]
...
```

Example Output:

```ps
List files from: ./my_files
File: image1.pdf >> REAL Type: jpg
File: document1.docx >> REAL Type: docx
...
```

## License

MIT License
