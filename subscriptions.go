/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package dns

// ChallengeEvent is the event that is emitted when a DNS challenge is created, updated, or deleted
type ChallengeEvent struct {
	// ID is the unique identifier of the dns challenge
	ID string

	// Deleted indicates whether the dns challenge was deleted
	Deleted bool

	// Challenge is the challenge that was created or updated.
	// If the challenge was deleted, this will be nil
	Challenge string
}

func (d *DNS) subscribeToChallengeEvents(events <-chan *ChallengeEvent) {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			d.logger.Info().Msg("challenge event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				d.logger.Debug().Msgf("challenge %s deleted", event.ID)
				d.dnsChallengesMu.Lock()
				delete(d.dnsChallenges, event.ID)
				d.dnsChallengesMu.Unlock()
			} else {
				d.logger.Debug().Msgf("challenge %s created or updated", event.ID)
				d.dnsChallengesMu.Lock()
				d.dnsChallenges[event.ID] = event.Challenge
				d.dnsChallengesMu.Unlock()
			}
		}
	}
}
