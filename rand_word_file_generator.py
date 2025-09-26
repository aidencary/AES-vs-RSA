import random
import os

def generate_word_list(num_words):
    """Generates a list of random words."""
    # A simple list of common words for demonstration
    common_words = [
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
        "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
        "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
        "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
        "so", "up", "out", "if", "about", "who", "get", "which", "go", "me"
    ]
    words = []
    for _ in range(num_words):
        words.append(random.choice(common_words))
    return words

def create_10kb_word_file(filename="10kb_words.txt"):
    """Creates a text file of approximately 10KB filled with words."""
    target_size_bytes = 10 * 1024  # 10KB in bytes
    
    # Use a more efficient approach: write directly to file and track size
    with open(filename, "w", encoding="utf-8") as f:
        current_size = 0
        batch_size = 100  # Smaller batch for smaller file
        
        while current_size < target_size_bytes:
            # Generate a batch of words
            words = generate_word_list(batch_size)
            content_batch = " ".join(words) + " "
            
            # Check if adding this batch would exceed the target
            batch_bytes = len(content_batch.encode('utf-8'))
            if current_size + batch_bytes > target_size_bytes:
                # Add words one by one until we reach the target
                for word in words:
                    word_with_space = word + " "
                    word_bytes = len(word_with_space.encode('utf-8'))
                    if current_size + word_bytes > target_size_bytes:
                        break
                    f.write(word_with_space)
                    current_size += word_bytes
                break
            else:
                # Write the entire batch
                f.write(content_batch)
                current_size += batch_bytes
    
    print(f"File '{filename}' created with size: {os.path.getsize(filename)} bytes")

def create_500kb_word_file(filename="500kb_words.txt"):
    """Creates a text file of approximately 500KB filled with words."""
    target_size_bytes = 500 * 1024  # 500KB in bytes
    
    # Use a more efficient approach: write directly to file and track size
    with open(filename, "w", encoding="utf-8") as f:
        current_size = 0
        batch_size = 1000  # Generate larger batches for efficiency
        
        while current_size < target_size_bytes:
            # Generate a batch of words
            words = generate_word_list(batch_size)
            content_batch = " ".join(words) + " "
            
            # Check if adding this batch would exceed the target
            batch_bytes = len(content_batch.encode('utf-8'))
            if current_size + batch_bytes > target_size_bytes:
                # Add words one by one until we reach the target
                for word in words:
                    word_with_space = word + " "
                    word_bytes = len(word_with_space.encode('utf-8'))
                    if current_size + word_bytes > target_size_bytes:
                        break
                    f.write(word_with_space)
                    current_size += word_bytes
                break
            else:
                # Write the entire batch
                f.write(content_batch)
                current_size += batch_bytes
    
    print(f"File '{filename}' created with size: {os.path.getsize(filename)} bytes")

def create_5mb_word_file(filename="5mb_words.txt"):
    """Creates a text file of approximately 5MB filled with words."""
    target_size_bytes = 5 * 1024 * 1024  # 5MB in bytes
    
    # Use a more efficient approach: write directly to file and track size
    with open(filename, "w", encoding="utf-8") as f:
        current_size = 0
        batch_size = 1000  # Generate larger batches for efficiency
        
        while current_size < target_size_bytes:
            # Generate a batch of words
            words = generate_word_list(batch_size)
            content_batch = " ".join(words) + " "
            
            # Check if adding this batch would exceed the target
            batch_bytes = len(content_batch.encode('utf-8'))
            if current_size + batch_bytes > target_size_bytes:
                # Add words one by one until we reach the target
                for word in words:
                    word_with_space = word + " "
                    word_bytes = len(word_with_space.encode('utf-8'))
                    if current_size + word_bytes > target_size_bytes:
                        break
                    f.write(word_with_space)
                    current_size += word_bytes
                break
            else:
                # Write the entire batch
                f.write(content_batch)
                current_size += batch_bytes
    
    print(f"File '{filename}' created with size: {os.path.getsize(filename)} bytes")

def benchmark_file_creation():
    """Benchmarks all file creation functions."""
    import time
    
    functions = [
        (create_10kb_word_file, "10KB"),
        (create_500kb_word_file, "500KB"), 
        (create_5mb_word_file, "5MB")
    ]
    
    for func, size_desc in functions:
        start_time = time.time()
        func()
        end_time = time.time()
        print(f"{size_desc} file creation took: {end_time - start_time:.3f} seconds")
        print()

if __name__ == "__main__":
    benchmark_file_creation()