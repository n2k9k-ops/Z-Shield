import { threatColor } from '@/lib/format';

/** Jauge de score de menace, façon vumètre. La couleur code le niveau. */
export function Risk({ score }: { score: number }) {
  return (
    <span className="risk">
      <span className="risk__track">
        <span className="risk__fill" style={{ width: `${Math.min(100, score)}%`, background: threatColor(score) }} />
      </span>
      <span className="risk__num">{score}</span>
    </span>
  );
}
