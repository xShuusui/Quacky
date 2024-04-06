from typing import Tuple
import sys

class TrieNode(object):
    """
    Our trie node implementation. Very basic. but does the job
    """
    
    def __init__(self, char: str):
        self.char = char
        self.children = []
        # Is it the last character of the word.`
        self.word_finished = False
        # How many times this character appeared in the addition process
        self.counter = 1
    

def add(root, word: str):
    """
    Adding a word in the trie structure
    """
    node = root
    for char in word:
        found_in_child = False
        # Search for the character in the children of the present `node`
        for child in node.children:
            if child.char == char:
                # We found it, increase the counter by 1 to keep track that another
                # word has it as well
                child.counter += 1
                # And point the node to the child that contains this char
                node = child
                found_in_child = True
                break
        # We did not find it so add a new chlid
        if not found_in_child:
            new_node = TrieNode(char)
            node.children.append(new_node)
            # And then point node to the new child
            node = new_node
    # Everything finished. Mark it as the end of a word.
    node.word_finished = True


def find_prefix(root, prefix: str) -> Tuple[bool, int]:
    """
    Check and return 
      1. If the prefix exsists in any of the words we added so far
      2. If yes then how may words actually have the prefix
    """
    node = root
    # If the root node has no children, then return False.
    # Because it means we are trying to search in an empty trie
    if not root.children:
        return False, 0
    for char in prefix:
        char_not_found = True
        # Search through all the children of the present `node`
        for child in node.children:
            if child.char == char:
                # We found the char existing in the child.
                char_not_found = False
                # Assign node as the child containing the char and break
                node = child
                break
        # Return False anyway when we did not find a char.
        if char_not_found:
            return False, 0
    # Well, we are here means we have found the prefix. Return true to indicate that
    # And also the counter of the last node. This indicates how many words have this
    # prefix
    return True, node.counter

def print_tree(root: TrieNode, level: int) -> None:
    
    finished_words = []
    nodes_to_process = []
    nodes_to_process.append((root,"",0))
    while len(nodes_to_process) > 0:
        curr_node,curr_word,curr_level = nodes_to_process.pop()
        curr_word = curr_word + curr_node.char

        # if a word finishes, add it to finished word
        if curr_node.word_finished:
            finished_words.append(curr_word)
            #print("here in 1")

        # if 1 child, continue path
        if len(curr_node.children) == 1:
            next_node = (curr_node.children[0],curr_word,curr_level)
            nodes_to_process.append(next_node)
        # if multiple children but level is max, then append wildcard and add to finished words
        elif curr_level == level and len(curr_node.children) > 1:
            finished_words.append(curr_word + '*')
        else:
            for child in curr_node.children:
                next_node = (child,curr_word,curr_level+1)
                nodes_to_process.append(next_node)
    
    return finished_words

if __name__ == "__main__":
    args = sys.argv[1:]
    filename = args[0]
    level = int(args[1])

    root = TrieNode('')
    with open(filename) as file:
        lines = [line.rstrip() for line in file]
    
    for line in lines:
        add(root, line)

    print_tree(root,level)

