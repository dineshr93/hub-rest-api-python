#!/bin/bash
input=$1
output=$2
# Check if inputs.txt exists
if [[ ! -f "${input}" ]]; then
    echo "Error: ${input} file not found!"
    exit 1
fi
# Check if output.txt exists
if [[ -f "${output}" ]]; then
    echo "Make empty ${output} file"
    > $output
fi
# Function to generate Maven URL
generate_url() {
    local input=$1
    # Split the input into group, artifact, and version
    IFS=':' read -r group artifact version <<< "$input"
    
    # Replace dots in the group ID with slashes
    group_url=$(echo "$group" | tr '.' '/')

    # Generate the initial URL for Google Maven repository
    google_url="https://dl.google.com/android/maven2/$group_url/$artifact/$version/$artifact-$version-sources.jar"

    # Validate the Google Maven URL
    if curl --head --silent --fail "$google_url" > /dev/null; then
        # If valid, append to the output file
        echo "$google_url" >> ${output}
    else
        # Try Maven Central Repository if Google Maven URL is invalid
        maven_url="https://repo1.maven.org/maven2/$group_url/$artifact/$version/$artifact-$version-sources.jar"
        
        # Validate the Maven Central URL
        if curl --head --silent --fail "$maven_url" > /dev/null; then
            # If valid, append it to the output file
            echo "$maven_url" >> ${output}
        else
            # Report invalid URL to the user
            echo "=================="
            echo "Invalid URL for both repositories: $input"
            echo "$google_url"
            echo "$maven_url"
            echo "=================="
        fi
    fi
}




# Read the inputs from inputs.txt file
# Use a while loop with a subshell to handle missing newline at the end
while IFS= read -r input || [[ -n "$input" ]]; do
    # Skip empty lines
    if [[ -n "$input" ]]; then
        generate_url "$input"
    fi
done < ${input}

# Notify the user that valid URLs have been written to the output file
echo " $(cat $output | wc -l) Valid Maven URLs have been written to ${output} <-------------"

