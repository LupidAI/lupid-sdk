/**
 * Reconstruct a hierarchy from the API's flat list of capabilities.
 *
 * Per Z3's Q-A pin, the Lupid API returns capabilities as a flat list with
 * `parent_id` pointers; the React component is responsible for building
 * the tree client-side. This module is intentionally pure (no React,
 * no DOM) so it can be unit-tested in isolation.
 *
 * Ordering:
 * - Roots and children are sorted by `display` (case-insensitive
 *   alphabetic), with `id` as the tiebreaker. When `display` is null, the
 *   `id` is used as the sort key.
 *
 * Orphan handling:
 * - A node whose `parent_id` points at an id that does not appear in the
 *   input list is treated as a root. The component renders it at the top
 *   level so the operator can still see it.
 */

import type { CapabilityNode } from "./types.js";

export interface TreeNode extends CapabilityNode {
  children: TreeNode[];
}

/** Case-insensitive locale compare of `display ?? id`. */
function sortKey(n: CapabilityNode): string {
  return (n.display ?? n.id).toLocaleLowerCase();
}

function compareNodes(a: CapabilityNode, b: CapabilityNode): number {
  const ka = sortKey(a);
  const kb = sortKey(b);
  if (ka < kb) return -1;
  if (ka > kb) return 1;
  if (a.id < b.id) return -1;
  if (a.id > b.id) return 1;
  return 0;
}

/**
 * Build a hierarchical tree from a flat list. O(N) in the input size.
 *
 * @param flat The list returned from `GET …/capabilities/`.
 * @returns The roots of the tree, each carrying their (recursively
 *          populated) `children` array.
 */
export function buildTree(flat: CapabilityNode[]): TreeNode[] {
  // Stage 1: wrap every input in a TreeNode with an empty children array,
  // keyed by id for O(1) parent lookup.
  const byId = new Map<string, TreeNode>();
  for (const n of flat) {
    byId.set(n.id, { ...n, children: [] });
  }

  // Stage 2: walk the input a second time and attach each non-root to its
  // parent. Orphans (parent_id unknown to the map) become roots.
  const roots: TreeNode[] = [];
  for (const n of flat) {
    const wrapped = byId.get(n.id);
    if (wrapped === undefined) {
      continue; // unreachable — populated in stage 1
    }
    if (n.parent_id === null) {
      roots.push(wrapped);
      continue;
    }
    const parent = byId.get(n.parent_id);
    if (parent === undefined) {
      // Orphan: parent_id points at an unknown id. Surface as a root so
      // it's visible to the operator.
      roots.push(wrapped);
      continue;
    }
    parent.children.push(wrapped);
  }

  // Stage 3: sort every level by (display, id).
  sortRecursive(roots);
  return roots;
}

function sortRecursive(nodes: TreeNode[]): void {
  nodes.sort(compareNodes);
  for (const n of nodes) {
    if (n.children.length > 0) {
      sortRecursive(n.children);
    }
  }
}
