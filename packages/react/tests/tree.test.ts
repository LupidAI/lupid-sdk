import { buildTree } from "../src/tree.js";
import type { CapabilityNode } from "../src/types.js";

function mk(partial: Partial<CapabilityNode> & { id: string }): CapabilityNode {
  return {
    id: partial.id,
    parent_id: partial.parent_id ?? null,
    display: partial.display ?? null,
    description: partial.description ?? null,
    risk: partial.risk ?? "low",
    customer_visible: partial.customer_visible ?? true,
    default: partial.default ?? "enabled",
    effective: partial.effective ?? true,
    override_value: partial.override_value ?? null,
  };
}

describe("buildTree", () => {
  it("returns an empty list for empty input", () => {
    expect(buildTree([])).toEqual([]);
  });

  it("treats a node with parent_id === null as a root", () => {
    const flat = [mk({ id: "cap.root" })];
    const tree = buildTree(flat);
    expect(tree).toHaveLength(1);
    expect(tree[0]?.id).toBe("cap.root");
    expect(tree[0]?.children).toEqual([]);
  });

  it("nests children under their parent and sorts alphabetically", () => {
    const flat = [
      mk({ id: "cap.root", display: "Root" }),
      mk({ id: "cap.b", parent_id: "cap.root", display: "Banana" }),
      mk({ id: "cap.a", parent_id: "cap.root", display: "Apple" }),
      mk({ id: "cap.c", parent_id: "cap.root", display: "Cherry" }),
    ];
    const tree = buildTree(flat);
    expect(tree).toHaveLength(1);
    expect(tree[0]?.children.map((c) => c.id)).toEqual(["cap.a", "cap.b", "cap.c"]);
  });

  it("falls back to id when display is null for sort order", () => {
    const flat = [
      mk({ id: "cap.root" }),
      mk({ id: "cap.zz", parent_id: "cap.root" }),
      mk({ id: "cap.aa", parent_id: "cap.root" }),
    ];
    const tree = buildTree(flat);
    expect(tree[0]?.children.map((c) => c.id)).toEqual(["cap.aa", "cap.zz"]);
  });

  it("uses id as a tiebreaker when display strings are equal", () => {
    const flat = [
      mk({ id: "cap.root", display: "root" }),
      mk({ id: "cap.b", parent_id: "cap.root", display: "Same" }),
      mk({ id: "cap.a", parent_id: "cap.root", display: "Same" }),
    ];
    const tree = buildTree(flat);
    expect(tree[0]?.children.map((c) => c.id)).toEqual(["cap.a", "cap.b"]);
  });

  it("promotes an orphan (parent_id points at unknown id) to a root", () => {
    const flat = [
      mk({ id: "cap.root", display: "Root" }),
      mk({ id: "cap.orphan", parent_id: "cap.gone", display: "Orphan" }),
    ];
    const tree = buildTree(flat);
    expect(tree).toHaveLength(2);
    expect(tree.map((r) => r.id).sort()).toEqual(["cap.orphan", "cap.root"]);
    const orphan = tree.find((r) => r.id === "cap.orphan");
    expect(orphan?.children).toEqual([]);
  });

  it("handles a deep tree (6 levels) without losing children", () => {
    // Build a chain: l0 → l1 → l2 → l3 → l4 → l5
    const flat: CapabilityNode[] = [];
    for (let i = 0; i <= 5; i += 1) {
      flat.push(
        mk({
          id: `cap.l${i}`,
          parent_id: i === 0 ? null : `cap.l${i - 1}`,
          display: `Level ${i}`,
        }),
      );
    }
    const tree = buildTree(flat);
    expect(tree).toHaveLength(1);
    let cursor = tree[0];
    for (let i = 0; i <= 5; i += 1) {
      expect(cursor?.id).toBe(`cap.l${i}`);
      cursor = cursor?.children[0];
    }
  });

  it("handles a balanced tree and sorts every level", () => {
    const flat = [
      mk({ id: "cap.root", display: "Root" }),
      mk({ id: "cap.b", parent_id: "cap.root", display: "B" }),
      mk({ id: "cap.a", parent_id: "cap.root", display: "A" }),
      mk({ id: "cap.b.2", parent_id: "cap.b", display: "B-2" }),
      mk({ id: "cap.b.1", parent_id: "cap.b", display: "B-1" }),
      mk({ id: "cap.a.2", parent_id: "cap.a", display: "A-2" }),
      mk({ id: "cap.a.1", parent_id: "cap.a", display: "A-1" }),
    ];
    const tree = buildTree(flat);
    expect(tree[0]?.children.map((c) => c.id)).toEqual(["cap.a", "cap.b"]);
    expect(tree[0]?.children[0]?.children.map((c) => c.id)).toEqual([
      "cap.a.1",
      "cap.a.2",
    ]);
    expect(tree[0]?.children[1]?.children.map((c) => c.id)).toEqual([
      "cap.b.1",
      "cap.b.2",
    ]);
  });

  it("does not mutate the input array", () => {
    const flat = [
      mk({ id: "cap.root", display: "Root" }),
      mk({ id: "cap.a", parent_id: "cap.root", display: "Apple" }),
    ];
    const snapshot = JSON.parse(JSON.stringify(flat)) as CapabilityNode[];
    buildTree(flat);
    expect(flat).toEqual(snapshot);
  });

  it("preserves every CapabilityNode field on cloned tree nodes", () => {
    const flat = [
      mk({
        id: "cap.root",
        display: "Root",
        description: "desc",
        risk: "high",
        customer_visible: false,
        default: "disabled",
        effective: false,
        override_value: false,
      }),
    ];
    const tree = buildTree(flat);
    const root = tree[0];
    expect(root).toMatchObject({
      id: "cap.root",
      display: "Root",
      description: "desc",
      risk: "high",
      customer_visible: false,
      default: "disabled",
      effective: false,
      override_value: false,
    });
  });
});
