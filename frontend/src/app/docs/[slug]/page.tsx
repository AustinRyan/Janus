import { notFound } from "next/navigation";
import {
  DOC_SECTIONS,
  getDocContent,
  getAllSlugs,
  getSectionsByCategory,
} from "../content";
import { DocsClient } from "./DocsClient";

export function generateStaticParams() {
  return getAllSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const section = DOC_SECTIONS.find((s) => s.slug === slug);
  if (!section) return {};
  return {
    title: `${section.title} — Janus Docs`,
    description: section.description,
  };
}

export default async function DocPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const content = getDocContent(slug);
  if (!content) notFound();

  const section = DOC_SECTIONS.find((s) => s.slug === slug)!;
  const categories = getSectionsByCategory();

  return (
    <DocsClient
      slug={slug}
      content={content}
      section={section}
      categories={categories}
    />
  );
}
