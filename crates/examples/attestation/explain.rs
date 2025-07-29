// Przykład: drzewo z 8 liśćmi, chcemy udowodnić liście [1, 2, 6]
//
//                    Root
//                 /        \
//              H01           H23
//            /    \        /     \
//         H0       H1    H2       H3
//        / \      / \   / \      /  \
//       0   1    2   3 4   5    6    7
//
// Chcemy udowodnić: liście [1, 2, 6]

use std::collections::HashMap;

fn main() {
    let sorted_leaf_indices = vec![1, 2, 6]; // Które liście chcemy udowodnić
    let total_leaves = 8; // Całkowita liczba liści w drzewie

    let result = proof_indices_by_layers(&sorted_leaf_indices, total_leaves);

    println!("Proof indices by layers: {:?}", result);

    // Wyjaśnienie krok po kroku
    explain_algorithm(&sorted_leaf_indices, total_leaves);
}

fn proof_indices_by_layers(sorted_leaf_indices: &[usize], leaves_count: usize) -> Vec<Vec<usize>> {
    let depth = tree_depth(leaves_count);
    println!("Tree depth: {}", depth);

    let mut layer_nodes = sorted_leaf_indices.to_vec();
    let mut proof_indices: Vec<Vec<usize>> = Vec::new();

    for layer_index in 0..depth {
        println!("\n=== LAYER {} ===", layer_index);
        println!("Current layer nodes: {:?}", layer_nodes);

        // 1. Znajdź siblings (rodzeństwo) dla każdego węzła
        let sibling_indices = sibling_indices(&layer_nodes);
        println!("Sibling indices: {:?}", sibling_indices);

        // 2. Które siblings już mamy? (są w layer_nodes)
        let already_have: Vec<usize> = sibling_indices
            .iter()
            .filter(|&&sibling| layer_nodes.contains(&sibling))
            .cloned()
            .collect();
        println!("Siblings we already have: {:?}", already_have);

        // 3. Które siblings musimy dołączyć do proof?
        let proof_nodes_indices: Vec<usize> = sibling_indices
            .iter()
            .filter(|&&sibling| !layer_nodes.contains(&sibling))
            .cloned()
            .collect();
        println!("Proof nodes needed: {:?}", proof_nodes_indices);

        proof_indices.push(proof_nodes_indices);

        // 4. Przejdź do następnej warstwy (parent nodes)
        layer_nodes = parent_indices(&layer_nodes);
        println!("Next layer (parents): {:?}", layer_nodes);
    }

    proof_indices
}

fn sibling_indices(indices: &[usize]) -> Vec<usize> {
    indices
        .iter()
        .map(|&i| {
            if i % 2 == 0 {
                i + 1 // Dla parzystego indeksu, sibling to i+1
            } else {
                i - 1 // Dla nieparzystego, sibling to i-1
            }
        })
        .collect()
}

fn parent_indices(indices: &[usize]) -> Vec<usize> {
    let mut parents: Vec<usize> = indices.iter().map(|&i| i / 2).collect();
    parents.sort();
    parents.dedup(); // Usuń duplikaty
    parents
}

fn tree_depth(leaves_count: usize) -> usize {
    if leaves_count <= 1 {
        0
    } else {
        (leaves_count - 1).ilog2() as usize + 1
    }
}

fn explain_algorithm(sorted_leaf_indices: &[usize], total_leaves: usize) {
    println!("\n🌳 WYJAŚNIENIE ALGORYTMU:");
    println!("Chcemy udowodnić liście: {:?}", sorted_leaf_indices);
    println!("Całkowita liczba liści: {}", total_leaves);

    println!("\n📊 Struktura drzewa (indeksy węzłów):");
    println!("Warstwa 0 (liście):     [0, 1, 2, 3, 4, 5, 6, 7]");
    println!("Warstwa 1:              [0, 1, 2, 3]"); // parent(0,1)=0, parent(2,3)=1, etc.
    println!("Warstwa 2:              [0, 1]");
    println!("Warstwa 3 (root):       [0]");

    println!("\n🔍 KROK PO KROKU:");

    println!("\n1️⃣ WARSTWA 0 (liście):");
    println!("   Mamy: [1, 2, 6]");
    println!("   Siblings: [0, 3, 7] (bo sibling(1)=0, sibling(2)=3, sibling(6)=7)");
    println!("   Już mamy: [] (żaden sibling nie jest w naszej liście)");
    println!("   Potrzebujemy: [0, 3, 7] ← te węzły muszą być w proof!");

    println!("\n2️⃣ WARSTWA 1:");
    println!("   Parents z [1,2,6]: [0,1,3] (bo parent(1)=0, parent(2)=1, parent(6)=3)");
    println!("   Siblings: [1,0,2] (bo sibling(0)=1, sibling(1)=0, sibling(3)=2)");
    println!("   Już mamy: [0,1] (bo 0 i 1 są w parents)");
    println!("   Potrzebujemy: [2] ← ten węzeł musi być w proof!");

    println!("\n3️⃣ WARSTWA 2:");
    println!("   Parents z [0,1,3]: [0,1] (bo parent(0)=0, parent(1)=0, parent(3)=1)");
    println!("   Po dedup: [0,1]");
    println!("   Siblings: [1,0]");
    println!("   Już mamy: [0,1] (wszystkich siblings już mamy!)");
    println!("   Potrzebujemy: [] ← nic więcej nie potrzeba!");

    println!("\n📦 WYNIK:");
    println!("   Warstwa 0: potrzebujemy węzłów [0, 3, 7]");
    println!("   Warstwa 1: potrzebujemy węzłów [2]");
    println!("   Warstwa 2: potrzebujemy węzłów []");
    println!("   RAZEM: [0, 3, 7, 2] hashy w proof zamiast 9 w trzech osobnych proof!");
}
